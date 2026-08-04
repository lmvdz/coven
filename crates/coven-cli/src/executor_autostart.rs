//! Per-user persistence for a fleet executor on Windows.
//!
//! The scheduled action deliberately runs the daemon in the foreground.  This
//! lets Task Scheduler observe failure and apply its restart policy.  The
//! registration contains paths only; fleet credentials remain in the normal
//! executor configuration below `COVEN_HOME`.

use std::fs;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REGISTRATION_FILE: &str = "executor-autostart.json";
const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registration {
    pub schema_version: u32,
    pub task_name: String,
    pub coven_home: PathBuf,
    pub executable_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutostartStatus {
    pub installed: bool,
    pub definition_matches: bool,
    pub task_state: Option<String>,
    pub daemon_running: bool,
    pub task_name: String,
    pub coven_home: PathBuf,
    pub executable_path: Option<PathBuf>,
}

/// Small seam around Task Scheduler, allowing lifecycle behavior to be tested
/// without registering a real task.
pub trait TaskScheduler {
    fn current_user_id(&self) -> Result<String>;
    fn task_xml(&self, task_name: &str) -> Result<Option<String>>;
    fn task_state(&self, task_name: &str) -> Result<Option<String>>;
    fn create_or_replace(&self, task_name: &str, xml: &str) -> Result<()>;
    fn run(&self, task_name: &str) -> Result<()>;
    fn end(&self, task_name: &str) -> Result<()>;
    fn delete(&self, task_name: &str) -> Result<()>;
}

pub fn registration_path(coven_home: &Path) -> PathBuf {
    coven_home.join(REGISTRATION_FILE)
}

pub fn task_name(coven_home: &Path) -> String {
    let normalized = normalized_home(coven_home);
    let digest = Sha256::digest(normalized.as_bytes());
    let suffix = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // A flat name avoids depending on a pre-existing Task Scheduler folder.
    format!("OpenCoven Fleet Executor {suffix}")
}

fn normalized_home(path: &Path) -> String {
    let value = path.to_string_lossy().replace('/', "\\");
    #[cfg(windows)]
    let value = value.to_lowercase();
    value.trim_end_matches('\\').to_owned()
}

pub fn make_registration(coven_home: &Path, executable: &Path) -> Result<Registration> {
    if !coven_home.is_absolute() || !executable.is_absolute() {
        bail!("Coven home and executable paths must be absolute");
    }
    Ok(Registration {
        schema_version: SCHEMA_VERSION,
        task_name: task_name(coven_home),
        coven_home: coven_home.to_path_buf(),
        executable_path: executable.to_path_buf(),
    })
}

pub fn load_registration(path: &Path) -> Result<Registration> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read autostart registration {}", path.display()))?;
    let registration: Registration = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid autostart registration {}", path.display()))?;
    if registration.schema_version != SCHEMA_VERSION {
        bail!(
            "unsupported autostart registration schema {}",
            registration.schema_version
        );
    }
    if registration.task_name != task_name(&registration.coven_home) {
        bail!("autostart registration task name does not match its Coven home");
    }
    Ok(registration)
}

fn save_registration(path: &Path, registration: &Registration) -> Result<()> {
    let parent = path
        .parent()
        .context("autostart registration has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(registration)?;
    fs::write(&temporary, bytes).with_context(|| format!("failed to stage {}", path.display()))?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(path);
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "failed to install {} after rename error: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

/// Quote one argument according to the Windows CommandLineToArgvW rules.
/// This is distinct from XML escaping and must happen first.
pub fn quote_windows_arg(value: &str) -> String {
    if !value.is_empty()
        && !value
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\n' | '\u{000b}' | '"'))
    {
        return value.to_owned();
    }
    let mut result = String::from("\"");
    let mut backslashes = 0usize;
    for character in value.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                result.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                result.push('"');
                backslashes = 0;
            }
            _ => {
                result.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                result.push(character);
            }
        }
    }
    result.extend(std::iter::repeat_n('\\', backslashes * 2));
    result.push('"');
    result
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn task_xml(registration: &Registration, registration_file: &Path, user_id: &str) -> String {
    let registration_argument = registration_file.to_string_lossy().into_owned();
    let arguments = [
        "executor",
        "autostart",
        "run",
        "--registration",
        registration_argument.as_str(),
    ]
    .into_iter()
    .map(quote_windows_arg)
    .collect::<Vec<_>>()
    .join(" ");
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT10S</Interval><Count>999</Count></RestartOnFailure></Settings>
  <Actions Context="Author"><Exec><Command>{command}</Command><Arguments>{arguments}</Arguments></Exec></Actions>
</Task>"#,
        user = xml_escape(user_id),
        command = xml_escape(&registration.executable_path.to_string_lossy()),
        arguments = xml_escape(&arguments),
    )
}

fn definition_matches(actual: &str, registration: &Registration, registration_file: &Path) -> bool {
    // schtasks normalizes and augments submitted XML, so byte equality is not
    // stable. Compare the security- and behavior-relevant leaves instead.
    let registration_argument = registration_file.to_string_lossy().into_owned();
    let arguments = [
        "executor",
        "autostart",
        "run",
        "--registration",
        registration_argument.as_str(),
    ]
    .into_iter()
    .map(quote_windows_arg)
    .collect::<Vec<_>>()
    .join(" ");
    [
        format!(
            "<Command>{}</Command>",
            xml_escape(&registration.executable_path.to_string_lossy())
        ),
        format!("<Arguments>{}</Arguments>", xml_escape(&arguments)),
        "<LogonType>InteractiveToken</LogonType>".into(),
        "<RunLevel>LeastPrivilege</RunLevel>".into(),
        "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>".into(),
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>".into(),
        "<RestartOnFailure>".into(),
    ]
    .iter()
    .all(|needle| actual.contains(needle))
}

/// Install or repair the task. `daemon_running` is kept separate from Task
/// Scheduler state because a registered task is not evidence of a healthy daemon.
pub fn install(
    scheduler: &dyn TaskScheduler,
    coven_home: &Path,
    executable: &Path,
    daemon_running: impl Fn(&Path) -> Result<bool>,
) -> Result<AutostartStatus> {
    let registration = make_registration(coven_home, executable)?;
    let path = registration_path(coven_home);
    let user = scheduler.current_user_id()?;
    let desired = task_xml(&registration, &path, &user);
    let existing = scheduler.task_xml(&registration.task_name)?;
    save_registration(&path, &registration)?;
    if !existing
        .as_deref()
        .is_some_and(|actual| definition_matches(actual, &registration, &path))
    {
        scheduler.create_or_replace(&registration.task_name, &desired)?;
    }
    let running = daemon_running(coven_home)?;
    if !running {
        scheduler.run(&registration.task_name)?;
    }
    status(scheduler, coven_home, |_| Ok(running))
}

pub fn status(
    scheduler: &dyn TaskScheduler,
    coven_home: &Path,
    daemon_running: impl Fn(&Path) -> Result<bool>,
) -> Result<AutostartStatus> {
    let path = registration_path(coven_home);
    let registration = load_registration(&path).ok();
    let name = registration
        .as_ref()
        .map(|r| r.task_name.clone())
        .unwrap_or_else(|| task_name(coven_home));
    let actual = scheduler.task_xml(&name)?;
    let definition_matches = actual.as_deref().is_some_and(|actual| {
        registration
            .as_ref()
            .is_some_and(|registration| definition_matches(actual, registration, &path))
    });
    Ok(AutostartStatus {
        installed: actual.is_some(),
        definition_matches,
        task_state: scheduler.task_state(&name)?,
        daemon_running: daemon_running(coven_home)?,
        task_name: name,
        coven_home: coven_home.to_path_buf(),
        executable_path: registration.map(|r| r.executable_path),
    })
}

pub fn uninstall(
    scheduler: &dyn TaskScheduler,
    coven_home: &Path,
    stop_daemon: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let registration_file = registration_path(coven_home);
    let had_registration = registration_file.exists();
    let name = load_registration(&registration_file)
        .map(|r| r.task_name)
        .unwrap_or_else(|_| task_name(coven_home));
    let installed = scheduler.task_xml(&name)?.is_some();
    if had_registration || installed {
        stop_daemon(coven_home)?;
    }
    if installed {
        let _ = scheduler.end(&name);
        scheduler.delete(&name)?;
    }
    match fs::remove_file(registration_file) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to remove autostart registration"),
    }
}

/// Hidden scheduled-task entrypoint. The callback should call
/// `daemon::serve_forever(home, timestamp, None, &[])` and must not detach.
pub fn run_foreground(
    registration_file: &Path,
    serve: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let registration = load_registration(registration_file)?;
    serve(&registration.coven_home)
}

#[derive(Debug, Default)]
#[cfg(windows)]
pub struct WindowsTaskScheduler;

#[cfg(windows)]
impl WindowsTaskScheduler {
    fn output(&self, args: &[&str]) -> Result<Output> {
        Command::new("schtasks.exe")
            .args(args)
            .output()
            .context("failed to launch schtasks.exe")
    }

    fn success(&self, args: &[&str], operation: &str) -> Result<()> {
        let output = self.output(args)?;
        if !output.status.success() {
            bail!(
                "Task Scheduler {operation} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }
}

fn decode_command_output(bytes: Vec<u8>) -> Result<String> {
    let has_utf16le_bom = bytes.starts_with(&[0xff, 0xfe]);
    let looks_like_utf16le = bytes.len().is_multiple_of(2)
        && bytes
            .chunks_exact(2)
            .take(64)
            .filter(|pair| pair[1] == 0)
            .count()
            >= bytes.chunks_exact(2).take(64).count().saturating_div(2);
    if has_utf16le_bom || looks_like_utf16le {
        let start = if has_utf16le_bom { 2 } else { 0 };
        if !(bytes.len() - start).is_multiple_of(2) {
            bail!("command returned malformed UTF-16LE output");
        }
        let units = bytes[start..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        return String::from_utf16(&units).context("command returned invalid UTF-16LE output");
    }
    String::from_utf8(bytes).context("command returned invalid UTF-8 output")
}

#[cfg(windows)]
impl TaskScheduler for WindowsTaskScheduler {
    fn current_user_id(&self) -> Result<String> {
        let output = Command::new("whoami.exe")
            .output()
            .context("failed to run whoami.exe")?;
        if !output.status.success() {
            bail!("whoami.exe failed");
        }
        let user = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if user.is_empty() {
            bail!("whoami.exe returned an empty user id");
        }
        Ok(user)
    }

    fn task_xml(&self, task_name: &str) -> Result<Option<String>> {
        let output = self.output(&["/Query", "/TN", task_name, "/XML"])?;
        if !output.status.success() {
            return Ok(None);
        }
        Ok(Some(
            decode_command_output(output.stdout)?.replace("\r\n", "\n"),
        ))
    }

    fn task_state(&self, task_name: &str) -> Result<Option<String>> {
        // State text is informational and localized; callers must not use it
        // as the daemon health signal.
        let output = self.output(&["/Query", "/TN", task_name, "/FO", "CSV", "/NH"])?;
        if !output.status.success() {
            return Ok(None);
        }
        Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        ))
    }

    fn create_or_replace(&self, task_name: &str, xml: &str) -> Result<()> {
        let temp = std::env::temp_dir().join(format!("coven-task-{}.xml", std::process::id()));
        let mut encoded = vec![0xff, 0xfe];
        for unit in xml.encode_utf16() {
            encoded.extend_from_slice(&unit.to_le_bytes());
        }
        fs::write(&temp, encoded)?;
        let result = self.success(
            &[
                "/Create",
                "/TN",
                task_name,
                "/XML",
                &temp.to_string_lossy(),
                "/F",
            ],
            "create",
        );
        let _ = fs::remove_file(temp);
        result
    }

    fn run(&self, task_name: &str) -> Result<()> {
        self.success(&["/Run", "/TN", task_name], "run")
    }
    fn end(&self, task_name: &str) -> Result<()> {
        self.success(&["/End", "/TN", task_name], "end")
    }
    fn delete(&self, task_name: &str) -> Result<()> {
        self.success(&["/Delete", "/TN", task_name, "/F"], "delete")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct FakeScheduler {
        xml: RefCell<Option<String>>,
        calls: RefCell<Vec<String>>,
    }
    impl TaskScheduler for FakeScheduler {
        fn current_user_id(&self) -> Result<String> {
            Ok(r"machine\user".into())
        }
        fn task_xml(&self, _: &str) -> Result<Option<String>> {
            Ok(self.xml.borrow().clone())
        }
        fn task_state(&self, _: &str) -> Result<Option<String>> {
            Ok(Some("Ready".into()))
        }
        fn create_or_replace(&self, _: &str, xml: &str) -> Result<()> {
            *self.xml.borrow_mut() = Some(xml.into());
            self.calls.borrow_mut().push("create".into());
            Ok(())
        }
        fn run(&self, _: &str) -> Result<()> {
            self.calls.borrow_mut().push("run".into());
            Ok(())
        }
        fn end(&self, _: &str) -> Result<()> {
            self.calls.borrow_mut().push("end".into());
            Ok(())
        }
        fn delete(&self, _: &str) -> Result<()> {
            self.xml.borrow_mut().take();
            self.calls.borrow_mut().push("delete".into());
            Ok(())
        }
    }

    #[test]
    fn windows_arguments_quote_backslashes_and_quotes() {
        assert_eq!(quote_windows_arg("plain"), "plain");
        assert_eq!(quote_windows_arg(""), r#""""#);
        assert_eq!(quote_windows_arg(r#"a b\"c"#), r#""a b\\\"c""#);
        assert_eq!(
            quote_windows_arg(r#"C:\with space\"#),
            r#""C:\with space\\""#
        );
    }

    #[test]
    fn command_output_decodes_utf16le_with_or_without_bom() -> Result<()> {
        let mut encoded = "<Task>ready</Task>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            decode_command_output(encoded.clone())?,
            "<Task>ready</Task>"
        );
        encoded.splice(0..0, [0xff, 0xfe]);
        assert_eq!(decode_command_output(encoded)?, "<Task>ready</Task>");
        Ok(())
    }

    #[test]
    fn xml_has_least_privilege_foreground_action_and_no_secret() -> Result<()> {
        let home = if cfg!(windows) {
            Path::new(r"C:\Users\Example & Co\fleet")
        } else {
            Path::new("/Users/Example & Co/fleet")
        };
        let executable = if cfg!(windows) {
            Path::new(r"C:\Applications\Coven & Co\coven.exe")
        } else {
            Path::new("/Applications/Coven & Co/coven.exe")
        };
        let registration_file = home.join("executor-autostart.json");
        let registration = make_registration(home, executable)?;
        let xml = task_xml(&registration, &registration_file, r"PC\Operator");
        assert!(xml.contains("InteractiveToken"));
        assert!(xml.contains("LeastPrivilege"));
        assert!(xml.contains("executor autostart run"));
        assert!(xml.contains("Example &amp; Co"));
        assert!(!xml.contains("nodeSecret"));
        assert!(!xml.contains("daemon start"));
        Ok(())
    }

    #[test]
    fn install_is_idempotent_and_skips_run_for_live_daemon() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let home = dir.path().join("home");
        let exe = dir.path().join("coven.exe");
        let scheduler = FakeScheduler::default();
        install(&scheduler, &home, &exe, |_| Ok(false))?;
        install(&scheduler, &home, &exe, |_| Ok(true))?;
        assert_eq!(&*scheduler.calls.borrow(), &["create", "run"]);
        let json = fs::read_to_string(registration_path(&home))?;
        assert!(!json.contains("secret"));
        Ok(())
    }

    #[test]
    fn uninstall_is_idempotent() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let home = dir.path().join("home");
        let exe = dir.path().join("coven.exe");
        let scheduler = FakeScheduler::default();
        install(&scheduler, &home, &exe, |_| Ok(true))?;
        uninstall(&scheduler, &home, |_| Ok(()))?;
        uninstall(&scheduler, &home, |_| Ok(()))?;
        assert!(!registration_path(&home).exists());
        Ok(())
    }

    #[test]
    fn foreground_runner_uses_only_the_registered_home() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let home = dir.path().join("home");
        let executable = dir.path().join("coven.exe");
        let registration = make_registration(&home, &executable)?;
        let path = registration_path(&home);
        save_registration(&path, &registration)?;

        run_foreground(&path, |actual_home| {
            assert_eq!(actual_home, home);
            Ok(())
        })
    }
}
