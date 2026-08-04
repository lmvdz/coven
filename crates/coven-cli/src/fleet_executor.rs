//! Executor-side fleet client and daemon worker.

use std::{
    ffi::{OsStr, OsString},
    fs::OpenOptions,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::{
    delegation, delegation_cleanup, delegation_executor,
    executor_control::{self, DesiredState, ExecutorOwner, RuntimeState},
    executor_node, fleet, harness_host, session_roam_executor, workspace_mobility,
};

const CONFIG_FILE: &str = "fleet-executor.json";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorFleetConfig {
    pub protocol_version: String,
    pub hub_url: String,
    pub node_id: String,
    pub node_secret: String,
    #[serde(default)]
    pub workspace_root: Option<PathBuf>,
}

const DEFAULT_EXECUTOR_WORKSPACE_DIR: &str = "executor-workspace";

fn executor_workspace_root(coven_home: &Path, configured_root: Option<&Path>) -> Result<PathBuf> {
    let root = configured_root
        .map(Path::to_path_buf)
        .unwrap_or_else(|| coven_home.join(DEFAULT_EXECUTOR_WORKSPACE_DIR));
    std::fs::create_dir_all(&root)
        .with_context(|| format!("failed to create executor workspace {}", root.display()))?;
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to resolve executor workspace {}", root.display()))?;
    if !root.is_dir() {
        bail!("executor workspace is not a directory: {}", root.display());
    }
    Ok(root)
}

struct HttpResponse {
    status: u16,
    body: String,
}

trait FleetTransport {
    fn post(&self, path: &str, bearer: Option<&str>, body: &Value) -> Result<HttpResponse>;
}

#[derive(Clone, Default)]
pub(crate) struct AttemptCancellation(Arc<AtomicBool>);

impl AttemptCancellation {
    fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub(crate) fn check(&self) -> Result<()> {
        if self.0.load(Ordering::Acquire) {
            bail!("fleet attempt lost authority")
        }
        Ok(())
    }
}

struct HttpFleetTransport {
    base: Url,
}

impl HttpFleetTransport {
    fn new(base: &str) -> Result<Self> {
        let mut base = Url::parse(base).context("fleet hub URL is invalid")?;
        if !matches!(base.scheme(), "http" | "https") {
            bail!("fleet hub URL must use http or https");
        }
        if base.host_str().is_none() {
            bail!("fleet hub URL requires a host");
        }
        base.set_path("");
        base.set_query(None);
        base.set_fragment(None);
        Ok(Self { base })
    }
}

impl FleetTransport for HttpFleetTransport {
    fn post(&self, path: &str, bearer: Option<&str>, body: &Value) -> Result<HttpResponse> {
        let host = self
            .base
            .host_str()
            .context("fleet hub URL lost its host")?;
        let port = self.base.port_or_known_default().unwrap_or(80);
        let body = serde_json::to_string(body)?;
        let mut tcp = TcpStream::connect((host, port))
            .with_context(|| format!("failed to connect to fleet hub {host}:{port}"))?;
        tcp.set_read_timeout(Some(Duration::from_secs(35)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
        let host_header = if self.base.port().is_some() {
            format!("{host}:{port}")
        } else {
            host.to_string()
        };
        let authorization = bearer
            .map(|token| format!("Authorization: Bearer {token}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\n{authorization}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        if self.base.scheme() == "https" {
            use rustls::pki_types::ServerName;
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server_name = ServerName::try_from(host.to_string())
                .context("fleet hub host is not a valid TLS server name")?;
            let connection =
                rustls::ClientConnection::new(std::sync::Arc::new(tls_config), server_name)?;
            let mut stream = rustls::StreamOwned::new(connection, tcp);
            return exchange_http(&mut stream, &request);
        }
        exchange_http(&mut tcp, &request)
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn exchange_http(stream: &mut dyn ReadWrite, request: &str) -> Result<HttpResponse> {
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let mut raw = Vec::new();
    stream
        .take((MAX_RESPONSE_BYTES + 64 * 1024) as u64)
        .read_to_end(&mut raw)?;
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("fleet hub returned a malformed HTTP response")?;
    let headers = std::str::from_utf8(&raw[..split])?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("fleet hub response omitted status")?
        .parse()?;
    let response_body = &raw[split + 4..];
    if response_body.len() > MAX_RESPONSE_BYTES {
        bail!("fleet hub response exceeded {MAX_RESPONSE_BYTES} bytes");
    }
    Ok(HttpResponse {
        status,
        body: String::from_utf8(response_body.to_vec())?,
    })
}

fn config_path(coven_home: &Path) -> PathBuf {
    coven_home.join(CONFIG_FILE)
}

pub fn load_config(coven_home: &Path) -> Result<Option<ExecutorFleetConfig>> {
    let path = config_path(coven_home);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()))
        }
    };
    let config: ExecutorFleetConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if config.protocol_version != fleet::FLEET_PROTOCOL_VERSION
        || config.node_id.trim().is_empty()
        || config.node_secret.trim().is_empty()
    {
        bail!("fleet executor configuration is invalid");
    }
    Ok(Some(config))
}

fn save_config(coven_home: &Path, config: &ExecutorFleetConfig) -> Result<()> {
    std::fs::create_dir_all(coven_home)?;
    let path = config_path(coven_home);
    let temporary = coven_home.join(format!(".{CONFIG_FILE}.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    serde_json::to_writer(&mut file, config)?;
    file.sync_all()?;
    std::fs::rename(&temporary, &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn local_capabilities(
    coven_home: &Path,
    workspace_binary: Option<&OsStr>,
) -> Result<fleet::NodeCapabilities> {
    let probe = executor_node::build_probe(coven_home)?;
    let workspace_drivers = match workspace_binary {
        Some(program) => ["filesystem", "s3-checkpoint"].into_iter().filter(|driver| workspace_mobility::invoke_with_binary(&json!({"protocolVersion": workspace_mobility::PROTOCOL_VERSION, "requestId": format!("probe-{driver}"), "driver": driver, "operation": "probe"}), program).is_ok()).map(str::to_string).collect(),
        None => workspace_mobility::probe(),
    };
    Ok(fleet::NodeCapabilities {
        protocols: fleet::ProtocolCapabilities {
            executor: vec![1],
            workspace_driver: (!workspace_drivers.is_empty())
                .then_some(1)
                .into_iter()
                .collect(),
            harness_host: vec![1],
        },
        platform: fleet::PlatformCapabilities {
            os: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            version: String::new(),
        },
        resources: fleet::ResourceCapabilities {
            cpu_cores: std::thread::available_parallelism()
                .map(|count| count.get() as u32)
                .unwrap_or(0),
            memory_bytes: 0,
        },
        gpu: None,
        runtimes: Default::default(),
        harnesses: vec!["fake".into()],
        workspace_drivers,
        tools: probe.capabilities,
    })
}

pub fn enroll(
    coven_home: &Path,
    hub: &str,
    node_id: &str,
    code: &str,
    workspace_root: Option<&Path>,
) -> Result<()> {
    if code.is_empty() {
        bail!("enrollment code is empty");
    }
    // Validate local execution state before redeeming the single-use code.
    let workspace_root = executor_workspace_root(coven_home, workspace_root)?;
    let transport = HttpFleetTransport::new(hub)?;
    let response = transport.post(
        "/api/v1/fleet/enrollments/redeem",
        None,
        &json!({
            "enrollmentCode": code,
            "nodeId": node_id,
            "capabilities": local_capabilities(coven_home, None)?,
        }),
    )?;
    if response.status != 201 {
        bail!(
            "fleet enrollment failed (HTTP {}): {}",
            response.status,
            response.body
        );
    }
    let value: Value = serde_json::from_str(&response.body)?;
    let secret = value["nodeSecret"]
        .as_str()
        .context("fleet enrollment response omitted nodeSecret")?;
    save_config(
        coven_home,
        &ExecutorFleetConfig {
            protocol_version: fleet::FLEET_PROTOCOL_VERSION.to_string(),
            hub_url: hub.trim_end_matches('/').to_string(),
            node_id: node_id.to_string(),
            node_secret: secret.to_string(),
            workspace_root: Some(workspace_root),
        },
    )
}

fn checked_response(response: HttpResponse, expected: &[u16], operation: &str) -> Result<Value> {
    if !expected.contains(&response.status) {
        bail!(
            "fleet {operation} failed (HTTP {}): {}",
            response.status,
            response.body
        );
    }
    if response.status == 204 || response.body.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&response.body).context("fleet hub returned invalid JSON")
}

fn run_once(
    transport: &dyn FleetTransport,
    coven_home: &Path,
    config: &ExecutorFleetConfig,
    workspace_binary: Option<&OsStr>,
) -> Result<()> {
    run_once_with_renewal_interval(
        transport,
        coven_home,
        config,
        workspace_binary,
        Duration::from_secs(10),
        25,
        || Ok(()),
    )
}

fn run_once_with_renewal_interval(
    transport: &dyn FleetTransport,
    coven_home: &Path,
    config: &ExecutorFleetConfig,
    workspace_binary: Option<&OsStr>,
    renewal_interval: Duration,
    claim_wait_seconds: u8,
    on_claimed: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let epoch = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
    checked_response(
        transport.post(
            &format!("/api/v1/fleet/nodes/{}/heartbeat", config.node_id),
            Some(&config.node_secret),
            &json!({
                "connectionEpoch": epoch,
                "capabilities": local_capabilities(coven_home, workspace_binary)?,
                "queuePressure": 0,
            }),
        )?,
        &[200],
        "heartbeat",
    )?;
    let claim = checked_response(
        transport.post(
            &format!(
                "/api/v1/fleet/nodes/{}/jobs/claim?wait={claim_wait_seconds}",
                config.node_id
            ),
            Some(&config.node_secret),
            &json!({}),
        )?,
        &[200, 204],
        "claim",
    )?;
    if claim.is_null() {
        return Ok(());
    }
    on_claimed()?;
    let job = &claim["job"];
    let job_id = job["jobId"].as_str().context("claim omitted jobId")?;
    let attempt_id = job["attemptId"]
        .as_str()
        .context("claim omitted attemptId")?;
    let lease_token = job["leaseToken"]
        .as_str()
        .context("claim omitted leaseToken")?;
    let mut payload = job["payload"].clone();
    if matches!(
        payload["protocolVersion"].as_str(),
        Some(delegation::PROTOCOL_VERSION | session_roam_executor::PROTOCOL_VERSION)
    ) {
        payload["attemptId"] = attempt_id.into();
        payload["nodeId"] = config.node_id.clone().into();
    }
    let workspace_binary: Option<OsString> = workspace_binary.map(OsStr::to_os_string);
    let coven_home_for_run = coven_home.to_path_buf();
    let configured_workspace_root = config.workspace_root.clone();

    let (sender, receiver) = mpsc::sync_channel(1);
    let job_id_for_run = job_id.to_string();
    let cancellation = AttemptCancellation::default();
    let worker_cancellation = cancellation.clone();
    let worker = std::thread::spawn(move || {
        let result = (|| -> Result<Value> {
            match payload["protocolVersion"].as_str() {
                Some(executor_node::EXECUTOR_PROTOCOL_VERSION) => {
                    let mut job: executor_node::ExecutorJob = serde_json::from_value(payload)
                        .context("claimed payload is not coven.executor.v1")?;
                    job.job_id = job_id_for_run;
                    if job.cwd.is_none() {
                        let executor_workspace = executor_workspace_root(
                            &coven_home_for_run,
                            configured_workspace_root.as_deref(),
                        )?;
                        job.cwd = Some(
                            executor_workspace
                                .to_str()
                                .context("executor workspace path is not valid UTF-8")?
                                .to_owned(),
                        );
                    }
                    Ok(serde_json::to_value(executor_node::run_job(&job))?)
                }
                Some(workspace_mobility::PROTOCOL_VERSION) => match workspace_binary.as_deref() {
                    Some(program) => workspace_mobility::invoke_with_binary(&payload, program),
                    None => workspace_mobility::invoke(&payload),
                },
                Some(harness_host::PROTOCOL_VERSION) => {
                    harness_host::invoke(&coven_home_for_run, &payload)
                }
                Some(delegation::PROTOCOL_VERSION) => delegation_executor::run(
                    &coven_home_for_run,
                    &payload,
                    workspace_binary.as_deref(),
                    &worker_cancellation,
                ),
                Some(delegation_cleanup::PROTOCOL_VERSION) => {
                    delegation_cleanup::run(&coven_home_for_run, &payload)
                }
                Some(session_roam_executor::PROTOCOL_VERSION) => session_roam_executor::run(
                    &coven_home_for_run,
                    &payload,
                    workspace_binary.as_deref(),
                    &worker_cancellation,
                ),
                _ => bail!("claimed payload uses an unsupported protocol"),
            }
        })();
        let _ = sender.send(result);
    });
    let mut lease_active = true;
    let execution = loop {
        match receiver.recv_timeout(renewal_interval) {
            Ok(result) => break result,
            Err(mpsc::RecvTimeoutError::Timeout) if lease_active => {
                let renewal = checked_response(
                    transport.post(
                        &format!("/api/v1/fleet/jobs/{job_id}/renew"),
                        Some(&config.node_secret),
                        &json!({"attemptId": attempt_id, "leaseToken": lease_token}),
                    )?,
                    &[200],
                    "lease renewal",
                );
                if let Err(error) = renewal {
                    lease_active = false;
                    cancellation.cancel();
                    eprintln!("coven daemon: fleet attempt {attempt_id} lost its lease: {error:#}");
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("fleet executor worker exited without a result")
            }
        }
    };
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("fleet executor worker panicked"))?;
    if !lease_active {
        return Ok(());
    }
    let result = match execution {
        Ok(result) => result,
        Err(error) => {
            let redacted = crate::privacy::redact_text(&format!("{error:#}"));
            let message = redacted.chars().take(1024).collect::<String>();
            checked_response(
                transport.post(
                    &format!("/api/v1/fleet/jobs/{job_id}/fail"),
                    Some(&config.node_secret),
                    &json!({
                        "attemptId": attempt_id,
                        "leaseToken": lease_token,
                        "completionKey": format!("fail:{attempt_id}"),
                        "failure": {"protocolVersion":fleet::FAILURE_PROTOCOL_VERSION,"code":"execution_failed","message":message},
                    }),
                )?,
                &[200],
                "failure",
            )?;
            return Ok(());
        }
    };
    checked_response(
        transport.post(
            &format!("/api/v1/fleet/jobs/{job_id}/complete"),
            Some(&config.node_secret),
            &json!({
                "attemptId": attempt_id,
                "leaseToken": lease_token,
                "completionKey": format!("complete:{attempt_id}"),
                "result": result,
            }),
        )?,
        &[200],
        "completion",
    )?;
    Ok(())
}

pub fn run_once_from_config(coven_home: &Path) -> Result<()> {
    let config =
        load_config(coven_home)?.context("this machine is not enrolled as a fleet executor")?;
    let transport = HttpFleetTransport::new(&config.hub_url)?;
    run_once(&transport, coven_home, &config, None)
}

pub fn start_if_configured(coven_home: &Path) -> Result<()> {
    if load_config(coven_home)?.is_none() || executor_control::has_managed_owner(coven_home) {
        return Ok(());
    }
    let home = coven_home.to_path_buf();
    std::thread::Builder::new()
        .name("coven-fleet-executor".into())
        .spawn(move || {
            if let Err(error) = serve_foreground(&home, ExecutorOwner::Legacy) {
                eprintln!("coven daemon: fleet executor: {error:#}");
            }
        })
        .context("failed to start fleet executor worker")?;
    Ok(())
}

/// Run the fleet polling lifecycle in this process/thread. The worker lock is
/// held for the whole call, so a desktop child, scheduled task, and legacy
/// daemon can never claim concurrently for one Coven home.
pub fn serve_foreground(coven_home: &Path, owner: ExecutorOwner) -> Result<()> {
    let config =
        load_config(coven_home)?.context("this machine is not enrolled as a fleet executor")?;
    let guard = executor_control::acquire_worker(coven_home, owner)?;
    loop {
        let control = executor_control::read_control(coven_home)?;
        if owner == ExecutorOwner::Legacy && control.owner != ExecutorOwner::Legacy {
            guard.publish(RuntimeState::Stopping)?;
            return Ok(());
        }
        match control.desired_state {
            DesiredState::Stopped => {
                guard.publish(RuntimeState::Stopping)?;
                return Ok(());
            }
            DesiredState::Paused => {
                guard.publish(RuntimeState::Paused)?;
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            DesiredState::Running => {}
        }
        guard.publish(RuntimeState::Claiming)?;
        let outcome = HttpFleetTransport::new(&config.hub_url).and_then(|transport| {
            run_once_with_renewal_interval(
                &transport,
                coven_home,
                &config,
                None,
                Duration::from_secs(10),
                2,
                || guard.publish(RuntimeState::Executing),
            )
        });
        guard.publish(RuntimeState::Idle)?;
        if let Err(error) = outcome {
            eprintln!("coven executor: fleet worker: {error:#}");
            std::thread::sleep(Duration::from_secs(2));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct ScriptedTransport {
        responses: Mutex<Vec<HttpResponse>>,
        requests: Mutex<Vec<(String, Option<String>, Value)>>,
    }

    struct InProcessTransport {
        hub_home: PathBuf,
    }

    #[test]
    fn foreground_worker_honors_durable_stop_before_network_claim() -> Result<()> {
        let home = tempfile::tempdir()?;
        save_config(
            home.path(),
            &ExecutorFleetConfig {
                protocol_version: fleet::FLEET_PROTOCOL_VERSION.into(),
                hub_url: "http://unreachable.invalid".into(),
                node_id: "stopped-node".into(),
                node_secret: "must-not-be-persisted-in-runtime".into(),
                workspace_root: None,
            },
        )?;
        executor_control::set_desired(
            home.path(),
            DesiredState::Stopped,
            Some(ExecutorOwner::Headless),
        )?;
        serve_foreground(home.path(), ExecutorOwner::Headless)?;
        let combined = std::fs::read_to_string(home.path().join("executor-control.json"))?;
        assert!(!combined.contains("must-not-be-persisted-in-runtime"));
        assert!(!home.path().join("executor-runtime.json").exists());
        Ok(())
    }

    fn assert_tree_omits(root: &Path, needles: &[&str]) -> Result<()> {
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    pending.push(entry.path());
                } else if kind.is_file() {
                    let bytes = std::fs::read(entry.path())?;
                    for needle in needles {
                        assert!(
                            !bytes
                                .windows(needle.len())
                                .any(|window| window == needle.as_bytes()),
                            "{} persisted secret material",
                            entry.path().display()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    impl FleetTransport for InProcessTransport {
        fn post(&self, path: &str, bearer: Option<&str>, body: &Value) -> Result<HttpResponse> {
            let authorization = bearer.map(|secret| format!("Bearer {secret}"));
            let response = crate::api::handle_request_with_runtime_and_auth(
                "POST",
                path,
                &self.hub_home,
                None,
                Some(&body.to_string()),
                &crate::api::NoopSessionRuntime,
                crate::api::RequestSecurity {
                    authorization: authorization.as_deref(),
                    local_transport: false,
                },
            )?;
            Ok(HttpResponse {
                status: response.status,
                body: response.body,
            })
        }
    }

    impl FleetTransport for ScriptedTransport {
        fn post(&self, path: &str, bearer: Option<&str>, body: &Value) -> Result<HttpResponse> {
            self.requests.lock().unwrap().push((
                path.into(),
                bearer.map(str::to_string),
                body.clone(),
            ));
            Ok(self.responses.lock().unwrap().remove(0))
        }
    }

    #[test]
    fn worker_claims_executes_and_completes_the_shared_envelope() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let cwd_command = if cfg!(windows) {
            json!(["cmd.exe", "/C", "cd"])
        } else {
            json!(["pwd"])
        };
        let payload = json!({
            "protocolVersion": "coven.executor.v1",
            "jobId": "placeholder",
            "requiredCapabilities": ["shell"],
            "command": cwd_command,
        });
        let transport = ScriptedTransport {
            responses: Mutex::new(vec![
                HttpResponse { status: 200, body: "{}".into() },
                HttpResponse { status: 200, body: json!({"job": {
                    "jobId": "job-1", "attemptId": "attempt-1", "leaseToken": "lease-1", "payload": payload
                }}).to_string() },
                HttpResponse { status: 200, body: "{}".into() },
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let config = ExecutorFleetConfig {
            protocol_version: fleet::FLEET_PROTOCOL_VERSION.into(),
            hub_url: "http://127.0.0.1:1".into(),
            node_id: "node-a".into(),
            node_secret: "test-node-secret".into(),
            workspace_root: None,
        };
        run_once(&transport, temp.path(), &config, None)?;
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].0.ends_with("/heartbeat"));
        assert!(requests[1].0.contains("/jobs/claim?wait=25"));
        assert!(requests[2].0.ends_with("/complete"));
        assert_eq!(requests[2].2["result"]["status"], "completed");
        let expected_workspace = temp
            .path()
            .join(DEFAULT_EXECUTOR_WORKSPACE_DIR)
            .canonicalize()?;
        let reported_workspace = requests[2].2["result"]["stdout"]
            .as_str()
            .context("result omitted stdout")?
            .trim();
        assert_eq!(
            Path::new(reported_workspace).canonicalize()?,
            expected_workspace
        );
        assert_eq!(requests[2].2["completionKey"], "complete:attempt-1");
        Ok(())
    }

    #[test]
    fn explicit_job_cwd_overrides_executor_workspace() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let configured_workspace = temp.path().join("configured");
        let explicit_workspace = temp.path().join("explicit");
        std::fs::create_dir_all(&explicit_workspace)?;
        let cwd_command = if cfg!(windows) {
            json!(["cmd.exe", "/C", "cd"])
        } else {
            json!(["pwd"])
        };
        let payload = json!({
            "protocolVersion": "coven.executor.v1",
            "jobId": "placeholder",
            "requiredCapabilities": ["shell"],
            "command": cwd_command,
            "cwd": explicit_workspace,
        });
        let transport = ScriptedTransport {
            responses: Mutex::new(vec![
                HttpResponse {
                    status: 200,
                    body: "{}".into(),
                },
                HttpResponse {
                    status: 200,
                    body: json!({"job": {
                        "jobId": "job-explicit", "attemptId": "attempt-explicit",
                        "leaseToken": "lease-explicit", "payload": payload
                    }})
                    .to_string(),
                },
                HttpResponse {
                    status: 200,
                    body: "{}".into(),
                },
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let config = ExecutorFleetConfig {
            protocol_version: fleet::FLEET_PROTOCOL_VERSION.into(),
            hub_url: "http://127.0.0.1:1".into(),
            node_id: "node-a".into(),
            node_secret: "test-node-secret".into(),
            workspace_root: Some(configured_workspace),
        };

        run_once(&transport, temp.path(), &config, None)?;

        let requests = transport.requests.lock().unwrap();
        let reported_workspace = requests[2].2["result"]["stdout"]
            .as_str()
            .context("result omitted stdout")?
            .trim();
        assert_eq!(
            Path::new(reported_workspace).canonicalize()?,
            explicit_workspace.canonicalize()?
        );
        assert!(!config.workspace_root.as_ref().unwrap().exists());
        Ok(())
    }

    #[test]
    fn execution_error_reports_typed_failure_instead_of_completion() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let transport = ScriptedTransport {
            responses: Mutex::new(vec![
                HttpResponse {
                    status: 200,
                    body: "{}".into(),
                },
                HttpResponse {
                    status: 200,
                    body: json!({"job": {
                        "jobId": "job-1", "attemptId": "attempt-1", "leaseToken": "lease-1",
                        "payload": {"protocolVersion":"unsupported"}
                    }})
                    .to_string(),
                },
                HttpResponse {
                    status: 200,
                    body: "{}".into(),
                },
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let config = ExecutorFleetConfig {
            protocol_version: fleet::FLEET_PROTOCOL_VERSION.into(),
            hub_url: "http://127.0.0.1:1".into(),
            node_id: "node-a".into(),
            node_secret: "test-node-secret".into(),
            workspace_root: None,
        };
        run_once(&transport, temp.path(), &config, None)?;
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[2].0.ends_with("/fail"));
        assert_eq!(requests[2].2["completionKey"], "fail:attempt-1");
        assert_eq!(
            requests[2].2["failure"]["protocolVersion"],
            fleet::FAILURE_PROTOCOL_VERSION
        );
        assert_eq!(requests[2].2["failure"]["code"], "execution_failed");
        assert!(requests
            .iter()
            .all(|request| !request.0.ends_with("/complete")));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn renewal_loss_quiesces_worker_without_reporting_stale_outcome() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let sentinel = temp.path().join("worker-finished");
        let payload = json!({
            "protocolVersion": executor_node::EXECUTOR_PROTOCOL_VERSION,
            "jobId": "placeholder",
            "requiredCapabilities": ["shell"],
            "command": ["sh", "-c", format!("sleep 0.05; touch {}", sentinel.display())],
        });
        let transport = ScriptedTransport {
            responses: Mutex::new(vec![
                HttpResponse { status: 200, body: "{}".into() },
                HttpResponse { status: 200, body: json!({"job": {
                    "jobId": "job-1", "attemptId": "attempt-1", "leaseToken": "lease-1", "payload": payload
                }}).to_string() },
                HttpResponse { status: 409, body: json!({"error":{"code":"lease_expired"}}).to_string() },
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let config = ExecutorFleetConfig {
            protocol_version: fleet::FLEET_PROTOCOL_VERSION.into(),
            hub_url: "http://127.0.0.1:1".into(),
            node_id: "node-a".into(),
            node_secret: "test-node-secret".into(),
            workspace_root: None,
        };
        run_once_with_renewal_interval(
            &transport,
            temp.path(),
            &config,
            None,
            Duration::from_millis(1),
            25,
            || Ok(()),
        )?;
        assert!(
            sentinel.exists(),
            "run_once returned before its worker quiesced"
        );
        let requests = transport.requests.lock().unwrap();
        assert!(requests.iter().any(|request| request.0.ends_with("/renew")));
        assert!(requests
            .iter()
            .all(|request| !request.0.ends_with("/complete") && !request.0.ends_with("/fail")));
        Ok(())
    }

    #[test]
    fn persisted_executor_config_is_owner_only_and_redacted_status_can_omit_secret() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let config = ExecutorFleetConfig {
            protocol_version: fleet::FLEET_PROTOCOL_VERSION.into(),
            hub_url: "http://127.0.0.1:3000".into(),
            node_id: "node-a".into(),
            node_secret: "test-node-secret".into(),
            workspace_root: None,
        };
        save_config(temp.path(), &config)?;
        assert_eq!(
            load_config(temp.path())?.unwrap().node_secret,
            "test-node-secret"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(config_path(temp.path()))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        Ok(())
    }

    #[test]
    fn legacy_executor_config_without_workspace_root_still_loads() -> Result<()> {
        let temp = tempfile::tempdir()?;
        std::fs::write(
            config_path(temp.path()),
            r#"{"protocolVersion":"coven.fleet.v1","hubUrl":"http://hub.invalid","nodeId":"legacy-node","nodeSecret":"legacy-secret"}"#,
        )?;

        let config = load_config(temp.path())?.context("legacy config did not load")?;

        assert_eq!(config.node_id, "legacy-node");
        assert_eq!(config.workspace_root, None);
        assert_eq!(
            executor_workspace_root(temp.path(), config.workspace_root.as_deref())?,
            temp.path()
                .join(DEFAULT_EXECUTOR_WORKSPACE_DIR)
                .canonicalize()?
        );
        Ok(())
    }

    #[test]
    fn executor_workspace_rejects_a_file() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let file = temp.path().join("not-a-workspace");
        std::fs::write(&file, "not a directory")?;

        let error = executor_workspace_root(temp.path(), Some(&file)).unwrap_err();

        assert!(error
            .to_string()
            .contains("failed to create executor workspace"));
        Ok(())
    }

    #[test]
    fn isolated_hub_and_executor_homes_offload_without_manual_receive() -> Result<()> {
        let hub = tempfile::tempdir()?;
        let executor = tempfile::tempdir()?;
        let issued = fleet::issue_enrollment(hub.path(), Some("{}"))?;
        let issued: Value = serde_json::from_str(&issued.body)?;
        let redeemed = fleet::redeem_enrollment(
            hub.path(),
            Some(
                &json!({
                    "enrollmentCode": issued["enrollmentCode"],
                    "nodeId": "executor-b",
                    "capabilities": local_capabilities(executor.path(), None)?,
                })
                .to_string(),
            ),
        )?;
        assert_eq!(redeemed.status, 201);
        let redeemed: Value = serde_json::from_str(&redeemed.body)?;
        let config = ExecutorFleetConfig {
            protocol_version: fleet::FLEET_PROTOCOL_VERSION.into(),
            hub_url: "http://hub.invalid".into(),
            node_id: "executor-b".into(),
            node_secret: redeemed["nodeSecret"].as_str().unwrap().into(),
            workspace_root: None,
        };
        save_config(executor.path(), &config)?;

        let hub_home = hub.path().to_path_buf();
        let offload = std::thread::spawn(move || {
            fleet::offload_tool(
                &hub_home,
                vec!["printf".into(), "automatic fleet output".into()],
                None,
                30,
                Duration::from_secs(5),
            )
        });
        std::thread::sleep(Duration::from_millis(50));
        run_once(
            &InProcessTransport {
                hub_home: hub.path().to_path_buf(),
            },
            executor.path(),
            &config,
            None,
        )?;
        let pulled = offload.join().expect("offload thread panicked")?;
        assert_eq!(pulled.status, executor_node::RESULT_STATUS_COMPLETED);
        assert_eq!(pulled.stdout, "automatic fleet output");

        let direct = executor_node::run_job(&executor_node::ExecutorJob {
            protocol_version: executor_node::EXECUTOR_PROTOCOL_VERSION.into(),
            job_id: pulled.job_id.clone(),
            hub_id: None,
            required_capabilities: vec!["shell".into()],
            command: vec!["printf".into(), "automatic fleet output".into()],
            cwd: None,
            env: Default::default(),
            stdin: None,
            timeout_seconds: Some(30),
            context: None,
        });
        assert_eq!(pulled.status, direct.status);
        assert_eq!(pulled.exit_code, direct.exit_code);
        assert_eq!(pulled.stdout, direct.stdout);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn workspace_request_is_leased_to_the_process_adapter() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let hub = tempfile::tempdir()?;
        let executor = tempfile::tempdir()?;
        let adapter = executor.path().join("coven-roam-test");
        std::fs::write(
            &adapter,
            "#!/bin/sh\nbody=$(cat)\nprintf '%s\\n' \"$body\" | sed 's/}$/,\"ok\":true}/'\n",
        )?;
        std::fs::set_permissions(&adapter, std::fs::Permissions::from_mode(0o700))?;

        let issued = fleet::issue_enrollment(hub.path(), Some("{}"))?;
        let issued: Value = serde_json::from_str(&issued.body)?;
        let redeemed = fleet::redeem_enrollment(
            hub.path(),
            Some(
                &json!({
                    "enrollmentCode": issued["enrollmentCode"],
                    "nodeId": "workspace-b",
                    "capabilities": local_capabilities(executor.path(), Some(adapter.as_os_str()))?,
                })
                .to_string(),
            ),
        )?;
        let redeemed: Value = serde_json::from_str(&redeemed.body)?;
        let invalid_workspace = executor.path().join("not-a-workspace");
        std::fs::write(&invalid_workspace, "actor protocol must ignore this")?;
        let config = ExecutorFleetConfig {
            protocol_version: fleet::FLEET_PROTOCOL_VERSION.into(),
            hub_url: "http://hub.invalid".into(),
            node_id: "workspace-b".into(),
            node_secret: redeemed["nodeSecret"].as_str().unwrap().into(),
            workspace_root: Some(invalid_workspace),
        };
        let request = json!({
            "protocolVersion": workspace_mobility::PROTOCOL_VERSION,
            "requestId": "release-1",
            "driver": "filesystem",
            "operation": "release"
        });
        let hub_home = hub.path().to_path_buf();
        let offload = std::thread::spawn(move || {
            fleet::offload_workspace(&hub_home, request, Duration::from_secs(5))
        });
        std::thread::sleep(Duration::from_millis(50));
        run_once(
            &InProcessTransport {
                hub_home: hub.path().to_path_buf(),
            },
            executor.path(),
            &config,
            Some(adapter.as_os_str()),
        )?;
        let result = offload.join().expect("workspace offload panicked")?;
        assert_eq!(
            result["protocolVersion"],
            workspace_mobility::PROTOCOL_VERSION
        );
        assert_eq!(result["requestId"], "release-1");
        assert_eq!(result["ok"], true);
        Ok(())
    }

    #[test]
    fn fake_harness_actor_start_send_status_and_stop_are_automatic() -> Result<()> {
        let hub = tempfile::tempdir()?;
        let executor = tempfile::tempdir()?;
        let issued: Value =
            serde_json::from_str(&fleet::issue_enrollment(hub.path(), Some("{}"))?.body)?;
        let redeemed = fleet::redeem_enrollment(
            hub.path(),
            Some(
                &json!({
                    "enrollmentCode": issued["enrollmentCode"], "nodeId": "actor-node",
                    "capabilities": local_capabilities(executor.path(), None)?,
                })
                .to_string(),
            ),
        )?;
        let redeemed: Value = serde_json::from_str(&redeemed.body)?;
        let invalid_workspace = executor.path().join("not-a-workspace");
        std::fs::write(&invalid_workspace, "actor protocol must ignore this")?;
        let config = ExecutorFleetConfig {
            protocol_version: fleet::FLEET_PROTOCOL_VERSION.into(),
            hub_url: "http://hub.invalid".into(),
            node_id: "actor-node".into(),
            node_secret: redeemed["nodeSecret"].as_str().unwrap().into(),
            workspace_root: Some(invalid_workspace),
        };
        let transport = InProcessTransport {
            hub_home: hub.path().to_path_buf(),
        };

        let perform = |request: Value| -> Result<Value> {
            let hub_home = hub.path().to_path_buf();
            let pending = std::thread::spawn(move || {
                fleet::offload_harness(&hub_home, request, Duration::from_secs(5))
            });
            std::thread::sleep(Duration::from_millis(50));
            run_once(&transport, executor.path(), &config, None)?;
            pending.join().expect("actor operation panicked")
        };
        let request = |id: &str, operation: &str| json!({"protocolVersion": harness_host::PROTOCOL_VERSION, "requestId": id, "operation": operation, "actorId": "actor-1"});
        let started = perform(
            json!({"protocolVersion": harness_host::PROTOCOL_VERSION, "requestId": "start", "operation": "start", "actorId": "actor-1", "harness": "fake", "generation": 1}),
        )?;
        assert_eq!(started["state"], "ready");
        let sent = perform(
            json!({"protocolVersion": harness_host::PROTOCOL_VERSION, "requestId": "send", "operation": "send", "actorId": "actor-1", "generation": 1, "idempotencyKey": "input-1", "input": "work"}),
        )?;
        assert_eq!(sent["output"], "fake:work");
        assert_eq!(perform(request("status", "status"))?["eventCount"], 3);
        assert_eq!(
            perform(
                json!({"protocolVersion": harness_host::PROTOCOL_VERSION, "requestId": "stop", "operation": "stop", "actorId": "actor-1", "generation": 1})
            )?["state"],
            "stopped"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn automatic_roam_checkpoints_prepares_activates_and_drains_input() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let hub = tempfile::tempdir()?;
        let executor_a = tempfile::tempdir()?;
        let executor_b = tempfile::tempdir()?;
        let adapter = hub.path().join("coven-roam-test");
        std::fs::write(
            &adapter,
            r#"#!/usr/bin/env python3
import gzip,hashlib,json,os,sys,tarfile
def norm(i):
 i.mtime=0; i.uid=0; i.gid=0; i.uname=""; i.gname=""; return i
r=json.load(sys.stdin); op=r["operation"]
if op=="probe": out={"protocolVersion":"coven.workspace-driver.v1","requestId":r["requestId"],"ok":True,"capabilities":{"portable":True}}
elif op=="checkpoint":
 p=r["locator"]["archivePath"]
 with open(p,"wb") as raw:
  with gzip.GzipFile(fileobj=raw,mode="wb",mtime=0) as gz:
   with tarfile.open(fileobj=gz,mode="w") as t:
    for n in sorted(os.listdir(r["workspacePath"])): t.add(os.path.join(r["workspacePath"],n),arcname=n,filter=norm)
 b=open(p,"rb").read(); out={"protocolVersion":"coven.workspace-driver.v1","requestId":r["requestId"],"ok":True,"checkpoint":{"driver":"filesystem","generation":r["generation"],"sha256":hashlib.sha256(b).hexdigest(),"sizeBytes":len(b),"locator":{"archivePath":p}}}
elif op=="restore":
 c=r["checkpoint"]; p=c["locator"]["archivePath"]; b=open(p,"rb").read()
 assert hashlib.sha256(b).hexdigest()==c["sha256"] and len(b)==c["sizeBytes"] and r["generation"]==c["generation"]
 os.mkdir(r["destinationPath"])
 with tarfile.open(p,"r:gz") as t: t.extractall(r["destinationPath"])
 out={"protocolVersion":"coven.workspace-driver.v1","requestId":r["requestId"],"ok":True}
else: out={"protocolVersion":"coven.workspace-driver.v1","requestId":r["requestId"],"ok":True}
json.dump(out,sys.stdout)
"#,
        )?;
        std::fs::set_permissions(&adapter, std::fs::Permissions::from_mode(0o700))?;

        let enroll = |node_id: &str, home: &Path| -> Result<ExecutorFleetConfig> {
            let issued: Value =
                serde_json::from_str(&fleet::issue_enrollment(hub.path(), Some("{}"))?.body)?;
            let redeemed = fleet::redeem_enrollment(
                hub.path(),
                Some(
                    &json!({"enrollmentCode":issued["enrollmentCode"],"nodeId":node_id,
                        "capabilities":local_capabilities(home,Some(adapter.as_os_str()))?})
                    .to_string(),
                ),
            )?;
            let redeemed: Value = serde_json::from_str(&redeemed.body)?;
            Ok(ExecutorFleetConfig {
                protocol_version: fleet::FLEET_PROTOCOL_VERSION.into(),
                hub_url: "http://hub.invalid".into(),
                node_id: node_id.into(),
                node_secret: redeemed["nodeSecret"].as_str().unwrap().into(),
                workspace_root: None,
            })
        };
        let config_a = enroll("node-a", executor_a.path())?;
        let config_b = enroll("node-b", executor_b.path())?;
        let provider_auth_sentinel = "provider-oauth-token-must-stay-on-node-a";
        std::fs::write(
            executor_a.path().join("provider-auth.json"),
            provider_auth_sentinel,
        )?;
        let transport = InProcessTransport {
            hub_home: hub.path().into(),
        };

        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        let now = crate::api::current_timestamp();
        crate::store::insert_session(
            &conn,
            &crate::store::SessionRecord {
                id: "session-roam".into(),
                project_root: "/portable/session-roam".into(),
                harness: "fake".into(),
                title: "automatic roam".into(),
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
        drop(conn);
        let source = crate::session_authority::begin_transfer(
            hub.path(),
            "session-roam",
            "node-a",
            "actor-source",
            &json!({}),
        )?;
        let source = crate::session_authority::activate_placement(
            hub.path(),
            "session-roam",
            &source.placement_id,
            source.generation,
            "node-a",
        )?;
        let source_workspace = crate::session_roam_executor::placement_workspace(
            executor_a.path(),
            "session-roam",
            &source.placement_id,
        )?;
        std::fs::create_dir_all(&source_workspace)?;
        std::fs::write(source_workspace.join("sentinel.txt"), "generation-one\n")?;
        let archive = hub.path().join("session-roam.tar.gz");
        let response = crate::api::handle_request_with_runtime_and_auth(
            "POST",
            "/api/v1/sessions/session-roam/roam",
            hub.path(),
            None,
            Some(
                &json!({"sourceNodeId":"node-a","targetNodeId":"node-b","targetHarness":"fake",
                    "workspace":{"driver":"filesystem","locator":{"archivePath":archive}}})
                .to_string(),
            ),
            &crate::api::NoopSessionRuntime,
            crate::api::RequestSecurity {
                authorization: None,
                local_transport: true,
            },
        )?;
        assert_eq!(response.status, 202, "{}", response.body);
        let started: Value = serde_json::from_str(&response.body)?;
        assert_eq!(started["generation"], 2);
        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        let saga: (String, String, String, String, String, String) = conn.query_row(
            "SELECT saga_id,state,actor_id,checkpoint_job_id,prepare_job_id,target_placement_id
             FROM session_roam_sagas WHERE session_id='session-roam'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
        let target_placement_id = saga.5.clone();
        assert_eq!(saga.1, "checkpoint_queued");
        let checkpoint_job: (String, String) = conn.query_row(
            "SELECT target_node_id,payload_json FROM hub_jobs WHERE job_id=?1",
            rusqlite::params![saga.3],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(checkpoint_job.0, "node-a");
        let checkpoint_payload: Value = serde_json::from_str(&checkpoint_job.1)?;
        assert_eq!(checkpoint_payload["operation"], "checkpoint-source");
        assert_eq!(checkpoint_payload["placementId"], source.placement_id);
        assert_eq!(checkpoint_payload["generation"], 1);
        drop(conn);
        assert!(crate::session_authority::begin_run(
            hub.path(),
            "session-roam",
            &source.placement_id,
            source.generation,
            "node-a"
        )
        .is_err());
        let input = crate::api::handle_request_with_body(
            "POST",
            "/api/v1/sessions/session-roam/input",
            hub.path(),
            None,
            Some(r#"{"data":"during-cutover"}"#),
        )?;
        assert_eq!(input.status, 202);
        assert!(input.body.contains(r#""queued":true"#));
        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        let queued: (i64, String, String) = conn.query_row(
            "SELECT sequence,state,payload_json FROM session_queued_inputs WHERE session_id='session-roam'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(queued.0, 1);
        assert_eq!(queued.1, "queued");
        assert_eq!(
            serde_json::from_str::<Value>(&queued.2)?,
            json!({"data":"during-cutover"})
        );
        drop(conn);

        run_once(
            &transport,
            executor_a.path(),
            &config_a,
            Some(adapter.as_os_str()),
        )?;
        assert!(crate::session_authority::active_placement(hub.path(), "session-roam")?.is_none());
        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        let checkpoint_json: String = conn.query_row(
            "SELECT checkpoint_json FROM session_roam_sagas WHERE session_id='session-roam'",
            [],
            |row| row.get(0),
        )?;
        let checkpoint: Value = serde_json::from_str(&checkpoint_json)?;
        assert_eq!(checkpoint["driver"], "filesystem");
        assert_eq!(checkpoint["generation"], 1);
        assert_eq!(
            checkpoint["locator"]["archivePath"],
            archive.to_string_lossy().as_ref()
        );
        assert!(checkpoint["sizeBytes"].as_u64().unwrap() > 0);
        assert!(!checkpoint["sha256"].as_str().unwrap().is_empty());
        let prepare_job: (String, String) = conn.query_row(
            "SELECT target_node_id,payload_json FROM hub_jobs WHERE job_id=?1",
            rusqlite::params![saga.4],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(prepare_job.0, "node-b");
        let prepare_payload: Value = serde_json::from_str(&prepare_job.1)?;
        assert_eq!(prepare_payload["operation"], "prepare-target");
        assert_eq!(prepare_payload["checkpoint"], checkpoint);
        assert_eq!(prepare_payload["placementId"], target_placement_id);
        assert_eq!(prepare_payload["actorId"], saga.2);
        drop(conn);
        let bearer_b = format!("Bearer {}", config_b.node_secret);
        let abandoned = fleet::claim_job(hub.path(), "node-b", Some(&bearer_b), 0)?;
        assert_eq!(abandoned.status, 200);
        let abandoned: Value = serde_json::from_str(&abandoned.body)?;
        let prepare_job_id = abandoned["job"]["jobId"].as_str().unwrap().to_string();
        let abandoned_attempt = abandoned["job"]["attemptId"].as_str().unwrap().to_string();
        let abandoned_lease = abandoned["job"]["leaseToken"].as_str().unwrap().to_string();
        let immutable_prepare = abandoned["job"]["payload"].clone();
        let abandoned_staging = executor_b
            .path()
            .join("session-roam-attempts")
            .join(&saga.0)
            .join(&abandoned_attempt)
            .join("staging-workspace");
        std::fs::create_dir_all(&abandoned_staging)?;
        std::fs::write(
            abandoned_staging.join("partial-restore.txt"),
            "must-not-promote",
        )?;
        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        conn.execute(
            "UPDATE fleet_job_attempts SET lease_expires_at='2000-01-01T00:00:00Z'
             WHERE job_id=?1 AND attempt_id=?2",
            rusqlite::params![prepare_job_id, abandoned_attempt],
        )?;
        drop(conn);
        run_once(
            &transport,
            executor_b.path(),
            &config_b,
            Some(adapter.as_os_str()),
        )?;
        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        let replacement_attempt: String = conn.query_row(
            "SELECT attempt_id FROM fleet_job_attempts WHERE job_id=?1",
            rusqlite::params![prepare_job_id],
            |row| row.get(0),
        )?;
        let raw_payload: String = conn.query_row(
            "SELECT payload_json FROM hub_jobs WHERE job_id=?1",
            rusqlite::params![prepare_job_id],
            |row| row.get(0),
        )?;
        drop(conn);
        assert_ne!(replacement_attempt, abandoned_attempt);
        assert_eq!(
            serde_json::from_str::<Value>(&raw_payload)?,
            immutable_prepare
        );
        let stale = fleet::complete_job(
            hub.path(),
            &prepare_job_id,
            Some(&bearer_b),
            Some(
                &json!({"attemptId":abandoned_attempt,"leaseToken":abandoned_lease,
                    "completionKey":"stale","result":{}})
                .to_string(),
            ),
        )?;
        assert_eq!(stale.status, 409);
        assert_eq!(
            serde_json::from_str::<Value>(&stale.body)?["error"]["code"],
            "attempt_mismatch"
        );
        let target = crate::session_authority::active_placement(hub.path(), "session-roam")?
            .context("target placement did not activate")?;
        assert_eq!(target.generation, 2);
        assert_eq!(target.node_id, "node-b");
        assert_eq!(target.placement_id, target_placement_id);
        assert_eq!(target.actor_id, saga.2);
        let target_workspace = crate::session_roam_executor::placement_workspace(
            executor_b.path(),
            "session-roam",
            &target.placement_id,
        )?;
        assert_eq!(
            std::fs::read_to_string(target_workspace.join("sentinel.txt"))?,
            "generation-one\n"
        );
        assert!(!target_workspace.join("partial-restore.txt").exists());
        let manifest: Value = serde_json::from_slice(&std::fs::read(
            target_workspace.parent().unwrap().join("manifest.json"),
        )?)?;
        assert_eq!(manifest["checkpointSha256"], checkpoint["sha256"]);
        assert_eq!(manifest["generation"], 2);
        assert_eq!(manifest["nodeId"], "node-b");
        assert_eq!(manifest["actorId"], saga.2);
        run_once(
            &transport,
            executor_b.path(),
            &config_b,
            Some(adapter.as_os_str()),
        )?;

        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        assert_eq!(
            conn.query_row(
                "SELECT state FROM session_queued_inputs WHERE session_id='session-roam'",
                [],
                |row| row.get::<_, String>(0)
            )?,
            "delivered"
        );
        let events = crate::store::list_events(&conn, "session-roam")?;
        assert_eq!(
            events.iter().filter(|event| event.kind == "input").count(),
            1
        );
        assert_eq!(
            events.iter().filter(|event| event.kind == "output").count(),
            1
        );
        let input_event = events.iter().find(|event| event.kind == "input").unwrap();
        let output_event = events.iter().find(|event| event.kind == "output").unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&input_event.payload_json)?,
            json!({"data":"during-cutover"})
        );
        assert_eq!(
            serde_json::from_str::<Value>(&output_event.payload_json)?,
            json!({"data":"fake:during-cutover"})
        );
        let lifecycle: (
            String,
            i64,
            String,
            Option<i64>,
            Option<String>,
            Option<String>,
        ) = conn.query_row(
            "SELECT logical_state,active_generation,active_placement_id,pending_generation,
                        pending_placement_id,fenced_placement_id
                 FROM session_lifecycles WHERE session_id='session-roam'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
        assert_eq!(
            lifecycle,
            (
                "open".into(),
                2,
                target.placement_id.clone(),
                None,
                None,
                None
            )
        );
        let placements: Vec<(String, String, i64, String, String)> = {
            let mut statement = conn.prepare(
                "SELECT placement_id,state,generation,node_id,actor_id FROM session_placements
                 WHERE session_id='session-roam' ORDER BY generation",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<_>>()?;
            rows
        };
        assert_eq!(placements.len(), 2);
        assert_eq!(
            placements[0],
            (
                source.placement_id.clone(),
                "released".into(),
                1,
                "node-a".into(),
                "actor-source".into()
            )
        );
        assert_eq!(
            placements[1],
            (
                target.placement_id.clone(),
                "active".into(),
                2,
                "node-b".into(),
                saga.2.clone()
            )
        );
        assert_eq!(
            placements
                .iter()
                .filter(|placement| placement.1 == "active")
                .count(),
            1
        );
        let saga_read: (String, Option<String>, Option<String>, String) = conn.query_row(
            "SELECT state,input_job_id,input_id,checkpoint_json FROM session_roam_sagas
             WHERE session_id='session-roam'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(saga_read.0, "active");
        assert_eq!(saga_read.1, None);
        assert_eq!(saga_read.2, None);
        assert_eq!(serde_json::from_str::<Value>(&saga_read.3)?, checkpoint);
        let before_late_a = (lifecycle.clone(), events.len());
        drop(conn);

        let late_a = crate::session_authority::accept_output(
            hub.path(),
            "session-roam",
            &source.placement_id,
            source.generation,
            "node-a",
        )
        .unwrap_err();
        assert_eq!(late_a.to_string(), "stale or unauthorized session output");

        crate::session_roam::reconcile_all(hub.path())?;
        crate::session_roam::reconcile_all(hub.path())?;
        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        let after_lifecycle: (
            String,
            i64,
            String,
            Option<i64>,
            Option<String>,
            Option<String>,
        ) = conn.query_row(
            "SELECT logical_state,active_generation,active_placement_id,pending_generation,
                        pending_placement_id,fenced_placement_id
                 FROM session_lifecycles WHERE session_id='session-roam'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
        assert_eq!(after_lifecycle, before_late_a.0);
        assert_eq!(
            crate::store::list_events(&conn, "session-roam")?.len(),
            before_late_a.1
        );
        assert_eq!(conn.query_row(
            "SELECT COUNT(*) FROM session_placements WHERE session_id='session-roam' AND state='active'",
            [],
            |row| row.get::<_, i64>(0),
        )?, 1);
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM hub_jobs WHERE job_id IN (?1,?2)",
                rusqlite::params![saga.3, saga.4],
                |row| row.get::<_, i64>(0),
            )?,
            2
        );
        drop(conn);

        let target_conn =
            crate::store::open_store(&executor_b.path().join(crate::STORE_FILE_NAME))?;
        let actor: (String, String, i64) = target_conn.query_row(
            "SELECT harness,state,generation FROM harness_actors WHERE actor_id=?1",
            rusqlite::params![saga.2],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(actor, ("fake".into(), "ready".into(), 2));
        assert_eq!(
            target_conn.query_row(
                "SELECT COUNT(*) FROM harness_actors WHERE actor_id=?1",
                rusqlite::params![saga.2],
                |row| row.get::<_, i64>(0),
            )?,
            1
        );
        drop(target_conn);

        assert_eq!(
            std::fs::read_to_string(executor_a.path().join("provider-auth.json"))?,
            provider_auth_sentinel
        );
        assert_tree_omits(hub.path(), &[provider_auth_sentinel])?;
        assert_tree_omits(executor_b.path(), &[provider_auth_sentinel])?;
        let secrets = [
            config_a.node_secret.as_str(),
            config_b.node_secret.as_str(),
            abandoned_lease.as_str(),
        ];
        assert_tree_omits(hub.path(), &secrets)?;
        assert_tree_omits(executor_a.path(), &secrets)?;
        assert_tree_omits(executor_b.path(), &secrets)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn remote_delegation_retains_until_ack_then_cleans_up_on_owner_node() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let hub = tempfile::tempdir()?;
        let executor = tempfile::tempdir()?;
        let parent = tempfile::tempdir()?;
        let adapter = executor.path().join("coven-roam-test");
        std::fs::write(
            &adapter,
            r#"#!/usr/bin/env python3
import gzip,hashlib,json,os,sys,tarfile
def norm(i):
 i.mtime=0; i.uid=0; i.gid=0; i.uname=""; i.gname=""; return i
r=json.load(sys.stdin); op=r["operation"]
if op=="probe": out={"protocolVersion":"coven.workspace-driver.v1","requestId":r["requestId"],"ok":True,"capabilities":{"portable":True}}
elif op=="checkpoint":
 p=r["locator"]["archivePath"]
 with open(p,"wb") as raw:
  with gzip.GzipFile(fileobj=raw,mode="wb",mtime=0) as gz:
   with tarfile.open(fileobj=gz,mode="w") as t:
    for n in sorted(os.listdir(r["workspacePath"])):
     if n not in (".git",".coven",".env",".env.local"): t.add(os.path.join(r["workspacePath"],n),arcname=n,filter=norm)
 b=open(p,"rb").read(); out={"protocolVersion":"coven.workspace-driver.v1","requestId":r["requestId"],"ok":True,"checkpoint":{"driver":"filesystem","generation":r["generation"],"sha256":hashlib.sha256(b).hexdigest(),"sizeBytes":len(b),"locator":{"archivePath":p}}}
elif op=="restore":
 c=r["checkpoint"]; p=c["locator"]["archivePath"]; b=open(p,"rb").read()
 assert hashlib.sha256(b).hexdigest()==c["sha256"] and len(b)==c["sizeBytes"] and r["generation"]==c["generation"]
 os.mkdir(r["destinationPath"])
 with tarfile.open(p,"r:gz") as t: t.extractall(r["destinationPath"])
 out={"protocolVersion":"coven.workspace-driver.v1","requestId":r["requestId"],"ok":True}
else: out={"protocolVersion":"coven.workspace-driver.v1","requestId":r["requestId"],"ok":True}
json.dump(out,sys.stdout)
"#,
        )?;
        std::fs::set_permissions(&adapter, std::fs::Permissions::from_mode(0o700))?;
        let git = |args: &[&str]| -> Result<String> {
            let output = std::process::Command::new("git")
                .args(args)
                .current_dir(parent.path())
                .output()?;
            if !output.status.success() {
                anyhow::bail!("git failed: {}", String::from_utf8_lossy(&output.stderr));
            }
            Ok(String::from_utf8(output.stdout)?.trim().into())
        };
        git(&["init", "-q"])?;
        git(&["config", "user.email", "test@example.invalid"])?;
        git(&["config", "user.name", "Test"])?;
        std::fs::write(parent.path().join("base.txt"), "base\n")?;
        git(&["add", "base.txt"])?;
        git(&["commit", "-qm", "base"])?;
        let base = git(&["rev-parse", "HEAD"])?;
        let base_archive = hub.path().join("base.tar.gz");
        let checkpoint = workspace_mobility::invoke_with_binary(
            &json!({"protocolVersion":workspace_mobility::PROTOCOL_VERSION,"requestId":"base","driver":"filesystem","operation":"checkpoint","workspacePath":parent.path(),"generation":1,"locator":{"archivePath":base_archive}}),
            adapter.as_os_str(),
        )?;

        let issued: Value =
            serde_json::from_str(&fleet::issue_enrollment(hub.path(), Some("{}"))?.body)?;
        let redeemed = fleet::redeem_enrollment(
            hub.path(),
            Some(&json!({"enrollmentCode":issued["enrollmentCode"],"nodeId":"delegate-node","capabilities":local_capabilities(executor.path(),Some(adapter.as_os_str()))?}).to_string()),
        )?;
        let redeemed: Value = serde_json::from_str(&redeemed.body)?;
        let config = ExecutorFleetConfig {
            protocol_version: fleet::FLEET_PROTOCOL_VERSION.into(),
            hub_url: "http://hub.invalid".into(),
            node_id: "delegate-node".into(),
            node_secret: redeemed["nodeSecret"].as_str().unwrap().into(),
            workspace_root: None,
        };
        let transport = InProcessTransport {
            hub_home: hub.path().into(),
        };
        let memory_sentinel = hub.path().join("canonical-memory-sentinel.json");
        std::fs::write(&memory_sentinel, r#"{"unchanged":true}"#)?;
        let started = delegation::start(
            hub.path(),
            delegation::DelegationRequest {
                protocol_version: delegation::PROTOCOL_VERSION.into(),
                delegation_id: Some("delegation-two-home".into()),
                parent_session_id: Some("parent-session".into()),
                parent_repo: parent.path().into(),
                base_revision: base,
                task: json!({"writeFiles":[{"path":"child.txt","content":"remote\n"}]}).to_string(),
                workspace_driver: "filesystem".into(),
                base_checkpoint: checkpoint["checkpoint"].clone(),
                result_locator: json!({"archivePath":hub.path().join("result.tar.gz")}),
                requirements: vec![],
                preferences: vec![],
                harness: "fake".into(),
            },
        )?;
        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        let now = crate::api::current_timestamp();
        crate::store::insert_session(
            &conn,
            &crate::store::SessionRecord {
                id: "parent-session".into(),
                project_root: parent.path().to_string_lossy().into_owned(),
                harness: "fake".into(),
                title: "active parent".into(),
                status: "running".into(),
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
        drop(conn);
        run_once(
            &transport,
            executor.path(),
            &config,
            Some(adapter.as_os_str()),
        )?;
        let allocation = executor
            .path()
            .join("delegations")
            .join(&started.delegation_id)
            .join(&started.child_id);
        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        let (attempt_id, observation_digest): (String, String) = conn.query_row(
            "SELECT attempt_id,placement_observation_digest FROM fleet_job_attempts WHERE job_id=?1",
            rusqlite::params![started.job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let attempt_root = allocation.join("attempts").join(&attempt_id);
        assert!(attempt_root.join("result.json").exists());
        let first_result: Value =
            serde_json::from_slice(&std::fs::read(attempt_root.join("result.json"))?)?;
        std::fs::remove_file(attempt_root.join("result.json"))?;
        let payload: String = conn.query_row(
            "SELECT payload_json FROM hub_jobs WHERE job_id=?1",
            rusqlite::params![started.job_id],
            |row| row.get(0),
        )?;
        drop(conn);
        let mut payload: Value = serde_json::from_str(&payload)?;
        payload["attemptId"] = attempt_id.into();
        payload["nodeId"] = "delegate-node".into();
        payload["placementObservationDigest"] = observation_digest.into();
        let replayed = delegation_executor::run(
            executor.path(),
            &payload,
            Some(adapter.as_os_str()),
            &AttemptCancellation::default(),
        )?;
        assert_eq!(replayed, first_result);
        assert!(!parent.path().join("child.txt").exists());
        let collected = delegation::collect(hub.path(), &started.delegation_id)?;
        assert_eq!(collected.state, "ready_to_integrate", "{collected:?}");
        assert!(
            allocation.exists(),
            "preview must retain executor resources"
        );

        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        conn.execute(
            "UPDATE fleet_delegations SET state='applying',finalization_key='finalize-1' WHERE delegation_id=?1",
            rusqlite::params![started.delegation_id],
        )?;
        drop(conn);
        delegation::reconcile_all(hub.path())?;
        let integrated = delegation::status(hub.path(), &started.delegation_id)?;
        assert_eq!(integrated.state, "cleanup_queued");
        assert_eq!(
            std::fs::read_to_string(parent.path().join("child.txt"))?,
            "remote\n"
        );
        assert!(allocation.exists(), "resources remain until cleanup ACK");
        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        let target: String = conn.query_row(
            "SELECT target_node_id FROM hub_jobs WHERE job_id=?1",
            rusqlite::params![integrated.cleanup_job_id],
            |row| row.get(0),
        )?;
        assert_eq!(target, "delegate-node");

        run_once(
            &transport,
            executor.path(),
            &config,
            Some(adapter.as_os_str()),
        )?;
        assert!(!allocation.exists());
        let finalized = delegation::collect(hub.path(), &started.delegation_id)?;
        assert_eq!(finalized.state, "finalized");
        assert!(finalized.cleanup_acknowledged);
        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        assert_eq!(
            crate::store::get_session(&conn, "parent-session")?
                .context("parent session disappeared")?
                .status,
            "running"
        );
        assert_eq!(
            std::fs::read_to_string(memory_sentinel)?,
            r#"{"unchanged":true}"#
        );
        let replay = delegation::integrate(hub.path(), &started.delegation_id, "finalize-1")?;
        assert_eq!(replay.cleanup_job_id, finalized.cleanup_job_id);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn executor_restart_waits_for_expiry_then_executes_one_replacement_attempt() -> Result<()> {
        let hub = tempfile::tempdir()?;
        let first_executor = tempfile::tempdir()?;
        let restarted_executor = tempfile::tempdir()?;
        let side_effect = hub.path().join("execution-count");

        let issued = fleet::issue_enrollment(hub.path(), Some("{}"))?;
        let issued: Value = serde_json::from_str(&issued.body)?;
        let redeemed = fleet::redeem_enrollment(
            hub.path(),
            Some(
                &json!({
                    "enrollmentCode": issued["enrollmentCode"],
                    "nodeId": "restart-executor",
                    "capabilities": local_capabilities(first_executor.path(), None)?,
                })
                .to_string(),
            ),
        )?;
        let redeemed: Value = serde_json::from_str(&redeemed.body)?;
        let config = ExecutorFleetConfig {
            protocol_version: fleet::FLEET_PROTOCOL_VERSION.into(),
            hub_url: "http://hub.invalid".into(),
            node_id: "restart-executor".into(),
            node_secret: redeemed["nodeSecret"].as_str().unwrap().into(),
            workspace_root: None,
        };
        save_config(first_executor.path(), &config)?;
        save_config(restarted_executor.path(), &config)?;
        let payload = serde_json::to_value(executor_node::ExecutorJob {
            protocol_version: executor_node::EXECUTOR_PROTOCOL_VERSION.into(),
            job_id: "restart-execution-job".into(),
            hub_id: None,
            required_capabilities: vec!["shell".into()],
            command: vec![
                "sh".into(),
                "-c".into(),
                format!("printf 'executed\\n' >> '{}'", side_effect.display()),
            ],
            cwd: None,
            env: Default::default(),
            stdin: None,
            timeout_seconds: Some(30),
            context: None,
        })?;
        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        fleet::submit_job_on_connection(
            &conn,
            "restart-execution-job",
            &payload,
            &["shell".into()],
            Some("restart-executor"),
        )?;
        drop(conn);
        let transport = InProcessTransport {
            hub_home: hub.path().to_path_buf(),
        };

        // The first process claims and then disappears before execution.
        let first_claim = transport.post(
            "/api/v1/fleet/nodes/restart-executor/jobs/claim",
            Some(&config.node_secret),
            &json!({}),
        )?;
        assert_eq!(first_claim.status, 200);
        let first_claim: Value = serde_json::from_str(&first_claim.body)?;
        assert!(!side_effect.exists());

        // A new process with the same durable node identity cannot steal the
        // still-live attempt and therefore performs no side effect.
        let restarted = load_config(restarted_executor.path())?.context("restart lost config")?;
        assert_eq!(restarted.node_id, config.node_id);
        assert_eq!(
            transport
                .post(
                    "/api/v1/fleet/nodes/restart-executor/jobs/claim",
                    Some(&restarted.node_secret),
                    &json!({}),
                )?
                .status,
            204
        );
        assert!(!side_effect.exists());

        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        conn.execute(
            "UPDATE fleet_job_attempts SET lease_expires_at='2000-01-01T00:00:00Z'
             WHERE job_id='restart-execution-job'",
            [],
        )?;
        drop(conn);

        run_once(&transport, restarted_executor.path(), &config, None)?;
        assert_eq!(std::fs::read_to_string(&side_effect)?, "executed\n");
        let conn = crate::store::open_store(&hub.path().join(crate::STORE_FILE_NAME))?;
        let terminal: (String, String, i64) = conn.query_row(
            "SELECT a.state,a.attempt_id,
             (SELECT COUNT(*) FROM fleet_job_attempts WHERE job_id='restart-execution-job')
             FROM fleet_job_attempts a WHERE a.job_id='restart-execution-job'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(terminal.0, "completed");
        assert_ne!(terminal.1, first_claim["job"]["attemptId"]);
        assert_eq!(terminal.2, 1, "one row owns terminal job authority");
        drop(conn);

        let stale_completion = json!({
            "attemptId": first_claim["job"]["attemptId"],
            "leaseToken": first_claim["job"]["leaseToken"],
            "completionKey": "stale-restart-completion",
            "result": {"status":"completed"},
        });
        assert_eq!(
            transport
                .post(
                    "/api/v1/fleet/jobs/restart-execution-job/complete",
                    Some(&config.node_secret),
                    &stale_completion,
                )?
                .status,
            409
        );
        assert_eq!(std::fs::read_to_string(side_effect)?, "executed\n");
        Ok(())
    }
}
