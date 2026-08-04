//! Redacted, local lifecycle state for the foreground fleet executor.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
#[cfg(any(windows, test))]
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "coven.executor-local.v1";
const CONTROL_FILE: &str = "executor-control.json";
const RUNTIME_FILE: &str = "executor-runtime.json";
const LOCK_FILE: &str = "executor.lock";
const STATE_LOCK_FILE: &str = "executor-state.lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredState {
    Running,
    Paused,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorOwner {
    Legacy,
    Desktop,
    Headless,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Starting,
    Idle,
    Claiming,
    Executing,
    Paused,
    Stopping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    Starting,
    Idle,
    Claiming,
    Executing,
    Paused,
    Stopping,
    Stopped,
    Stale,
}

impl From<RuntimeState> for ObservationState {
    fn from(value: RuntimeState) -> Self {
        match value {
            RuntimeState::Starting => Self::Starting,
            RuntimeState::Idle => Self::Idle,
            RuntimeState::Claiming => Self::Claiming,
            RuntimeState::Executing => Self::Executing,
            RuntimeState::Paused => Self::Paused,
            RuntimeState::Stopping => Self::Stopping,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlState {
    pub protocol_version: String,
    pub desired_state: DesiredState,
    pub owner: ExecutorOwner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRecord {
    pub protocol_version: String,
    pub pid: u32,
    pub started_at: String,
    pub updated_at: String,
    pub state: RuntimeState,
    pub owner: ExecutorOwner,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalStatus {
    pub protocol_version: &'static str,
    pub configured: bool,
    pub desired_state: DesiredState,
    pub runtime_state: ObservationState,
    pub running: bool,
    pub stale: bool,
    pub pid: Option<u32>,
    pub started_at: Option<String>,
    pub updated_at: Option<String>,
    pub owner: ExecutorOwner,
    pub node_id: Option<String>,
    pub workspace_root: Option<PathBuf>,
}

pub struct WorkerGuard {
    _lock: File,
    home: PathBuf,
    pid: u32,
    owner: ExecutorOwner,
}

#[derive(Debug)]
#[cfg(any(windows, test))]
pub struct IdleWorkerGuard {
    _lock: File,
    home: PathBuf,
}

fn path(home: &Path, name: &str) -> PathBuf {
    home.join(name)
}

fn state_lock(home: &Path) -> Result<File> {
    fs::create_dir_all(home)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path(home, STATE_LOCK_FILE))?;
    lock.lock_exclusive()
        .context("failed to lock executor lifecycle state")?;
    Ok(lock)
}

fn atomic_json_locked(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("executor state path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    use std::io::Write;
    file.write_all(&bytes)?;
    file.sync_all()?;
    replace_file(&temporary, path)?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(temporary: &Path, destination: &Path) -> Result<()> {
    fs::rename(temporary, destination).context("failed to atomically replace executor state")
}

#[cfg(windows)]
fn replace_file(temporary: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let source = temporary
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let target = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to atomically replace executor state");
    }
    Ok(())
}

pub fn read_control(home: &Path) -> Result<ControlState> {
    let _lock = state_lock(home)?;
    read_control_locked(home)
}

fn read_control_locked(home: &Path) -> Result<ControlState> {
    let file = path(home, CONTROL_FILE);
    if !file.exists() {
        return Ok(ControlState {
            protocol_version: PROTOCOL_VERSION.into(),
            desired_state: DesiredState::Running,
            owner: ExecutorOwner::Legacy,
        });
    }
    let state: ControlState =
        serde_json::from_slice(&fs::read(&file)?).context("invalid executor control state")?;
    if state.protocol_version != PROTOCOL_VERSION {
        bail!("unsupported executor control protocol");
    }
    Ok(state)
}

pub fn set_desired(
    home: &Path,
    desired_state: DesiredState,
    owner: Option<ExecutorOwner>,
) -> Result<ControlState> {
    let _lock = state_lock(home)?;
    let mut state = read_control_locked(home)?;
    state.desired_state = desired_state;
    if let Some(owner) = owner {
        state.owner = owner;
    }
    atomic_json_locked(&path(home, CONTROL_FILE), &state)?;
    Ok(state)
}

pub fn has_managed_owner(home: &Path) -> bool {
    read_control(home)
        .map(|state| state.owner != ExecutorOwner::Legacy)
        .unwrap_or(true)
        || home.join("executor-autostart.json").exists()
}

pub fn acquire_worker(home: &Path, owner: ExecutorOwner) -> Result<WorkerGuard> {
    fs::create_dir_all(home)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path(home, LOCK_FILE))?;
    lock.try_lock_exclusive()
        .context("another fleet executor worker already owns this Coven home")?;
    let _state_lock = state_lock(home)?;
    let control = read_control_locked(home)?;
    if owner == ExecutorOwner::Desktop
        && (home.join("executor-autostart.json").exists()
            || control.owner == ExecutorOwner::Headless)
    {
        bail!("headless executor ownership is installed; uninstall autostart before desktop serve");
    }
    let desired = if owner == ExecutorOwner::Desktop {
        DesiredState::Running
    } else {
        control.desired_state
    };
    let state = ControlState {
        protocol_version: PROTOCOL_VERSION.into(),
        desired_state: desired,
        owner,
    };
    atomic_json_locked(&path(home, CONTROL_FILE), &state)?;
    let pid = std::process::id();
    let now = now();
    atomic_json_locked(
        &path(home, RUNTIME_FILE),
        &RuntimeRecord {
            protocol_version: PROTOCOL_VERSION.into(),
            pid,
            started_at: now.clone(),
            updated_at: now,
            state: RuntimeState::Starting,
            owner,
        },
    )?;
    Ok(WorkerGuard {
        _lock: lock,
        home: home.to_path_buf(),
        pid,
        owner,
    })
}

impl WorkerGuard {
    pub fn publish(&self, state: RuntimeState) -> Result<()> {
        let _lock = state_lock(&self.home)?;
        let file = path(&self.home, RUNTIME_FILE);
        let started_at = fs::read(&file)
            .ok()
            .and_then(|b| serde_json::from_slice::<RuntimeRecord>(&b).ok())
            .filter(|r| r.pid == self.pid)
            .map(|r| r.started_at)
            .unwrap_or_else(now);
        atomic_json_locked(
            &file,
            &RuntimeRecord {
                protocol_version: PROTOCOL_VERSION.into(),
                pid: self.pid,
                started_at,
                updated_at: now(),
                state,
                owner: self.owner,
            },
        )
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        let Ok(_lock) = state_lock(&self.home) else {
            return;
        };
        let file = path(&self.home, RUNTIME_FILE);
        if fs::read(&file)
            .ok()
            .and_then(|b| serde_json::from_slice::<RuntimeRecord>(&b).ok())
            .is_some_and(|r| r.pid == self.pid)
        {
            let _ = fs::remove_file(file);
        }
    }
}

pub fn status(
    home: &Path,
    configured: bool,
    node_id: Option<String>,
    workspace_root: Option<PathBuf>,
) -> Result<LocalStatus> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path(home, LOCK_FILE))?;
    let (running, _idle_guard) = match lock.try_lock_exclusive() {
        Ok(()) => (false, Some(lock)),
        Err(_) => (true, None),
    };
    let _state_lock = state_lock(home)?;
    let control = read_control_locked(home)?;
    let runtime = fs::read(path(home, RUNTIME_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<RuntimeRecord>(&b).ok());
    let stale = runtime.is_some() && !running;
    let runtime_state = if stale {
        ObservationState::Stale
    } else if running {
        runtime
            .as_ref()
            .map(|r| r.state.into())
            .unwrap_or(ObservationState::Starting)
    } else {
        ObservationState::Stopped
    };
    let configured_owner = if control.owner == ExecutorOwner::Legacy
        && home.join("executor-autostart.json").exists()
    {
        ExecutorOwner::Headless
    } else {
        control.owner
    };
    let owner = if running {
        runtime
            .as_ref()
            .map(|r| r.owner)
            .unwrap_or(configured_owner)
    } else {
        configured_owner
    };
    Ok(LocalStatus {
        protocol_version: PROTOCOL_VERSION,
        configured,
        desired_state: control.desired_state,
        runtime_state,
        running,
        stale,
        pid: runtime.as_ref().map(|r| r.pid),
        started_at: runtime.as_ref().map(|r| r.started_at.clone()),
        updated_at: runtime.as_ref().map(|r| r.updated_at.clone()),
        owner,
        node_id,
        workspace_root,
    })
}

/// Request a graceful stop and prove exclusive ownership of the worker slot.
/// The returned guard must remain alive across an ownership/task transaction.
#[cfg(any(windows, test))]
pub fn drain_and_lock(home: &Path, timeout: Duration) -> Result<IdleWorkerGuard> {
    set_desired(home, DesiredState::Stopped, None)?;
    let deadline = Instant::now() + timeout;
    loop {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path(home, LOCK_FILE))?;
        if lock.try_lock_exclusive().is_ok() {
            return Ok(IdleWorkerGuard {
                _lock: lock,
                home: home.to_path_buf(),
            });
        }
        if Instant::now() >= deadline {
            bail!("fleet executor is still active; wait for current work to drain, then retry");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(any(windows, test))]
impl IdleWorkerGuard {
    pub fn transfer(&self, owner: ExecutorOwner, desired_state: DesiredState) -> Result<()> {
        let _lock = state_lock(&self.home)?;
        atomic_json_locked(
            &path(&self.home, CONTROL_FILE),
            &ControlState {
                protocol_version: PROTOCOL_VERSION.into(),
                desired_state,
                owner,
            },
        )
    }
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_and_runtime_are_redacted_and_duplicate_guarded() -> Result<()> {
        let home = tempfile::tempdir()?;
        set_desired(
            home.path(),
            DesiredState::Running,
            Some(ExecutorOwner::Desktop),
        )?;
        let guard = acquire_worker(home.path(), ExecutorOwner::Desktop)?;
        guard.publish(RuntimeState::Executing)?;
        assert!(acquire_worker(home.path(), ExecutorOwner::Desktop).is_err());
        let text = format!(
            "{}{}",
            fs::read_to_string(path(home.path(), CONTROL_FILE))?,
            fs::read_to_string(path(home.path(), RUNTIME_FILE))?
        );
        for forbidden in ["nodeSecret", "leaseToken", "job", "provider"] {
            assert!(!text.contains(forbidden));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for file in [CONTROL_FILE, RUNTIME_FILE] {
                assert_eq!(
                    fs::metadata(path(home.path(), file))?.permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        let observed = status(home.path(), true, Some("node-a".into()), None)?;
        assert!(observed.running);
        assert_eq!(observed.runtime_state, ObservationState::Executing);
        drop(guard);
        assert!(!status(home.path(), true, None, None)?.running);
        assert_eq!(
            status(home.path(), true, None, None)?.runtime_state,
            ObservationState::Stopped
        );
        Ok(())
    }

    #[test]
    fn desired_state_survives_worker_restart() -> Result<()> {
        let home = tempfile::tempdir()?;
        set_desired(
            home.path(),
            DesiredState::Paused,
            Some(ExecutorOwner::Headless),
        )?;
        let guard = acquire_worker(home.path(), ExecutorOwner::Headless)?;
        assert_eq!(
            read_control(home.path())?.desired_state,
            DesiredState::Paused
        );
        drop(guard);
        assert_eq!(read_control(home.path())?.owner, ExecutorOwner::Headless);
        Ok(())
    }

    #[test]
    fn managed_owner_suppresses_legacy_embedding() -> Result<()> {
        let home = tempfile::tempdir()?;
        assert!(!has_managed_owner(home.path()));
        set_desired(
            home.path(),
            DesiredState::Paused,
            Some(ExecutorOwner::Desktop),
        )?;
        assert!(has_managed_owner(home.path()));
        Ok(())
    }

    #[test]
    fn desktop_start_rejects_headless_coexistence_and_restart_requests_running() -> Result<()> {
        let home = tempfile::tempdir()?;
        fs::write(home.path().join("executor-autostart.json"), b"{}")?;
        assert!(acquire_worker(home.path(), ExecutorOwner::Desktop).is_err());
        fs::remove_file(home.path().join("executor-autostart.json"))?;
        set_desired(
            home.path(),
            DesiredState::Stopped,
            Some(ExecutorOwner::Desktop),
        )?;
        let guard = acquire_worker(home.path(), ExecutorOwner::Desktop)?;
        assert_eq!(
            read_control(home.path())?.desired_state,
            DesiredState::Running
        );
        drop(guard);
        Ok(())
    }

    #[test]
    fn desktop_to_headless_transfer_requires_idle_worker_lock() -> Result<()> {
        let home = tempfile::tempdir()?;
        let desktop = acquire_worker(home.path(), ExecutorOwner::Desktop)?;
        let error = drain_and_lock(home.path(), Duration::from_millis(20)).unwrap_err();
        assert!(error.to_string().contains("still active"));
        drop(desktop);
        let transfer = drain_and_lock(home.path(), Duration::from_secs(1))?;
        transfer.transfer(ExecutorOwner::Headless, DesiredState::Running)?;
        drop(transfer);
        let headless = acquire_worker(home.path(), ExecutorOwner::Headless)?;
        let observed = status(home.path(), true, None, None)?;
        assert_eq!(observed.owner, ExecutorOwner::Headless);
        assert!(observed.running);
        drop(headless);
        Ok(())
    }
}
