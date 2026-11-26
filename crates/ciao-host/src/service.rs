#[cfg(target_os = "linux")]
mod linux_process;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};

use crate::storage::{CiaoPaths, atomic_write_private};

pub const LAUNCH_AGENT_LABEL: &str = "app.ciaooo.ciao.daemon";
const LEGACY_LAUNCH_AGENT_LABEL: &str = "com.bojanstef.ciao.daemon";
pub const SYSTEMD_UNIT_NAME: &str = "ciao.service";

/// Whether lingering keeps the per-user service alive after logout (Linux only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LingerStatus {
    Enabled,
    Disabled,
    Unknown,
    NotApplicable,
}

/// Which supervisor actually took ownership of the daemon. Ciao installs the best one the
/// host offers and never picks a weaker rung when a stronger one is usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervisor {
    Launchd,
    SystemdUser {
        linger: LingerStatus,
    },
    /// A `@reboot` crontab entry. Starts the daemon at boot and survives logout, but cannot
    /// restart it on crash.
    CronReboot {
        reason: CronReason,
    },
}

/// Why the boot task was chosen. These need different explanations: one host has no service
/// manager, the other has a perfectly good one that simply would not survive a logout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CronReason {
    NoUserManager,
    LingeringDisabled,
}

/// Which Linux rung to prefer.
///
/// A systemd user unit outranks a boot task only when lingering is enabled. Without it,
/// `user@<uid>.service` starts at first login and stops at last logout, so the unit never
/// starts at boot and dies the moment the operator disconnects — useless for a host whose
/// entire purpose is being reachable from a phone. A `@reboot` entry survives both, needs no
/// privilege, and only gives up crash restart. Reachability is the product promise, so it
/// outranks crash restart here.
///
/// `Unknown` lingering is treated as not-enabled: claiming persistence we have not confirmed
/// is the failure that actually costs the operator something.
pub fn preferred_linux_rung(manager: UserManager, linger: LingerStatus) -> Supervisor {
    match (manager, linger) {
        (UserManager::Ready, LingerStatus::Enabled) => Supervisor::SystemdUser {
            linger: LingerStatus::Enabled,
        },
        (UserManager::Ready, _) => Supervisor::CronReboot {
            reason: CronReason::LingeringDisabled,
        },
        _ => Supervisor::CronReboot {
            reason: CronReason::NoUserManager,
        },
    }
}

pub const CRON_BEGIN: &str = "# >>> ciao managed block (do not edit; `ciao reset` removes it)";
pub const CRON_END: &str = "# <<< ciao managed block";

fn join_crontab(lines: &[&str]) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Strips Ciao's managed block, leaving every other byte of the operator's crontab intact.
///
/// A `BEGIN` with no matching `END` drops only that one marker line. Skipping to end-of-file
/// would delete entries Ciao never wrote, and a crontab is the kind of thing people keep a
/// decade of scheduling in.
pub fn crontab_without_ciao(existing: &str) -> String {
    let lines: Vec<&str> = existing.lines().collect();
    let mut kept: Vec<&str> = Vec::with_capacity(lines.len());
    let mut index = 0;
    while index < lines.len() {
        if lines[index].trim() == CRON_BEGIN {
            match (index + 1..lines.len()).find(|&end| lines[end].trim() == CRON_END) {
                Some(end) => index = end + 1,
                None => index += 1,
            }
            continue;
        }
        kept.push(lines[index]);
        index += 1;
    }
    join_crontab(&kept)
}

/// Replaces Ciao's managed block, appending it if absent. Idempotent: applying this twice
/// yields the same crontab, because the old block is removed before the new one is written.
pub fn crontab_with_ciao(existing: &str, command: &str) -> String {
    let mut out = crontab_without_ciao(existing);
    out.push_str(CRON_BEGIN);
    out.push('\n');
    out.push_str("@reboot ");
    out.push_str(command);
    out.push('\n');
    out.push_str(CRON_END);
    out.push('\n');
    out
}

/// `%` is a newline inside a crontab command and would split our entry in two; quotes and
/// backslashes would break the quoting that lets paths contain spaces.
fn cron_field(path: &Path, what: &str) -> Result<String> {
    if !path.is_absolute() {
        bail!("{what} must be absolute");
    }
    let Some(text) = path.to_str() else {
        bail!("{what} must be valid UTF-8");
    };
    if text
        .bytes()
        .any(|byte| matches!(byte, b'%' | b'"' | b'\\' | b'\n' | b'\r' | b'$' | b'`'))
    {
        bail!("{what} contains characters unsupported in a crontab entry");
    }
    Ok(text.to_owned())
}

/// Builds the crontab command field. Output is redirected to the daemon's own log because
/// cron mails whatever a job prints to the operator, which would arrive on every boot.
pub fn cron_command(executable: &Path, log: &Path) -> Result<String> {
    let executable = cron_field(executable, "daemon executable path")?;
    let log = cron_field(log, "daemon log path")?;
    Ok(format!("\"{executable}\" daemon >> \"{log}\" 2>&1"))
}

/// What is supervising the daemon right now, read from the host rather than from what setup
/// intended. Nothing recorded the chosen rung, so answering "what is keeping this alive"
/// required inspecting the unit and the crontab by hand — which is exactly what a compatibility
/// run on Rocky had to do, and it reported the gap as a failure.
pub fn describe_supervisor() -> String {
    #[cfg(target_os = "macos")]
    {
        let uid = nix::unistd::Uid::effective().as_raw();
        let service = format!("gui/{uid}/{LAUNCH_AGENT_LABEL}");
        let loaded = Command::new("launchctl")
            .args(["print", service.as_str()])
            .output()
            .is_ok_and(|output| output.status.success());
        if loaded {
            "launchd agent".to_owned()
        } else {
            "none — the daemon is not under a supervisor".to_owned()
        }
    }
    #[cfg(target_os = "linux")]
    {
        let unit_active = systemctl_user(&["--user", "is-active", SYSTEMD_UNIT_NAME])
            .output()
            .is_ok_and(|output| ciao_unit_active(&String::from_utf8_lossy(&output.stdout)));
        if unit_active {
            return match detect_linger() {
                LingerStatus::Enabled => "systemd user unit, lingering enabled".to_owned(),
                // Worth stating plainly: this unit stops at logout and never starts at boot.
                _ => "systemd user unit — lingering disabled, so it stops when you log out"
                    .to_owned(),
            };
        }
        if read_crontab().is_ok_and(|table| table.lines().any(|line| line.trim() == CRON_BEGIN)) {
            return "@reboot boot task (no crash restart)".to_owned();
        }
        "none — the daemon is not under a supervisor".to_owned()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "unknown".to_owned()
    }
}

/// Readiness must come from the process the selected supervisor started.
pub struct InstalledService {
    pub supervisor: Supervisor,
    pub expected_pid: Option<i32>,
    // Serializes rung changes until the caller finishes verifying local health.
    _transaction: Option<fs::File>,
}

/// Installs or repairs the platform per-user service with fixed argv: launchd on macOS,
/// a per-user systemd unit on Linux (Spec 004 §8.2). Identity and pairing files are never
/// touched here.
pub fn install_service(paths: &CiaoPaths, executable: &Path) -> Result<InstalledService> {
    #[cfg(target_os = "macos")]
    {
        install_launch_agent(paths, executable)?;
        Ok(InstalledService {
            supervisor: Supervisor::Launchd,
            expected_pid: None,
            _transaction: None,
        })
    }
    #[cfg(target_os = "linux")]
    {
        install_linux_service(paths, executable)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (paths, executable);
        bail!("this host platform is unsupported by the Ciao alpha");
    }
}

// ---------------------------------------------------------------------------
// macOS launchd
// ---------------------------------------------------------------------------

pub fn launch_agent_plist(paths: &CiaoPaths, executable: &Path) -> Result<String> {
    if !executable.is_absolute() {
        bail!("daemon executable path must be absolute");
    }
    let executable = xml_escape(&executable.to_string_lossy());
    let stdout = xml_escape(&paths.stdout_log.to_string_lossy());
    let stderr = xml_escape(&paths.stderr_log.to_string_lossy());
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCH_AGENT_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{executable}</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <!-- Not Background, which is what this was until 2026-08-20. `ProcessType: Background` puts
       the job in PRIO_DARWIN_BG, and every process it spawns inherits that — on Apple silicon
       that means E-cores only. Measured on this machine with three real launchd jobs running
       the same slash-command probe: Background reported PRI 4 and 61.7 s, Standard reported
       PRI 20 and 1.59 s. Adaptive also reported PRI 4, because launchd only promotes an
       Adaptive job that holds an XPC transaction and this daemon never takes one; it is not
       the middle setting it reads as. The same tax is why warming the CLI digest at startup
       takes 110-150 s here where a shell takes 14 s.
       Background is for work nobody is waiting on. A phone waiting on its terminal is not
       that, and an idle daemon at 0.4% CPU is not competing with anything by being Standard. -->
  <key>ProcessType</key>
  <string>Standard</string>
  <key>StandardOutPath</key>
  <string>{stdout}</string>
  <key>StandardErrorPath</key>
  <string>{stderr}</string>
</dict>
</plist>
"#
    ))
}

pub fn install_launch_agent(paths: &CiaoPaths, executable: &Path) -> Result<()> {
    paths.ensure_layout()?;
    ensure_log_file(&paths.stdout_log)?;
    ensure_log_file(&paths.stderr_log)?;

    let uid = nix::unistd::Uid::effective().as_raw();
    let domain = format!("gui/{uid}");
    retire_legacy_launch_agent(paths, &domain)?;

    let plist = launch_agent_plist(paths, executable)?;
    atomic_write_private(&paths.service_file, plist.as_bytes())?;
    let service = format!("{domain}/{LAUNCH_AGENT_LABEL}");

    // A missing current service is the normal first-install case, so bootout is intentionally
    // best effort. bootstrap and kickstart below are authoritative and are never shell-composed.
    let _ = Command::new("launchctl")
        .args(["bootout", service.as_str()])
        .output();

    let plist_path = paths.service_file.to_string_lossy().into_owned();
    bootstrap_with_retry(&domain, &plist_path, paths)?;

    let kickstart = Command::new("launchctl")
        .args(["kickstart", "-k", service.as_str()])
        .output()
        .context("execute launchctl kickstart")?;
    require_success("launchctl kickstart", &kickstart, paths)?;
    Ok(())
}

fn bootstrap_with_retry(domain: &str, plist_path: &str, paths: &CiaoPaths) -> Result<()> {
    // launchd can return EIO briefly after a successful bootout while it finishes removing the
    // old job. Retry the exact argv for a bounded interval so setup remains idempotent.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let output = Command::new("launchctl")
            .args(["bootstrap", domain, plist_path])
            .output()
            .context("execute launchctl bootstrap")?;
        if output.status.success() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return require_success("launchctl bootstrap", &output, paths);
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn legacy_launch_agent_file(paths: &CiaoPaths) -> PathBuf {
    paths
        .service_file
        .with_file_name(format!("{LEGACY_LAUNCH_AGENT_LABEL}.plist"))
}

fn retire_legacy_launch_agent(paths: &CiaoPaths, domain: &str) -> Result<()> {
    let service = format!("{domain}/{LEGACY_LAUNCH_AGENT_LABEL}");
    // The provisional alpha used the legacy label. Stop it before bootstrapping the settled label
    // so an upgrade cannot leave two daemons racing for the same state and local IPC socket.
    let _ = Command::new("launchctl")
        .args(["bootout", service.as_str()])
        .output();
    let probe = Command::new("launchctl")
        .args(["print", service.as_str()])
        .output()
        .context("verify legacy launchd service stopped")?;
    if probe.status.success() {
        bail!(
            "legacy launchd service {LEGACY_LAUNCH_AGENT_LABEL} remained loaded after bootout; \
             the host identity was preserved. Stop it manually and rerun `ciao setup --yes`."
        );
    }

    let legacy_file = legacy_launch_agent_file(paths);
    match fs::remove_file(&legacy_file) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("remove {}", legacy_file.display()));
        }
    }
    Ok(())
}

fn ensure_log_file(path: &Path) -> Result<()> {
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure log file {}", path.display()))?;
    } else {
        atomic_write_private(path, b"")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Linux per-user systemd
// ---------------------------------------------------------------------------

/// Deterministic per-user unit (Spec 004 §8.2). Fixed absolute argv, no shell, no environment
/// interpolation, and `KillMode=process` so a service stop or update never cgroup-kills durable
/// tmux/Herdr session servers; the daemon performs its own bounded graceful cleanup of owned
/// plain shells.
pub fn systemd_unit(executable: &Path, stdout_log: &Path, stderr_log: &Path) -> Result<String> {
    if !executable.is_absolute() {
        bail!("daemon executable path must be absolute");
    }
    let Some(text) = executable.to_str() else {
        bail!("daemon executable path must be valid UTF-8");
    };
    if text
        .bytes()
        .any(|byte| matches!(byte, b'"' | b'\\' | b'\n' | b'%'))
    {
        bail!("daemon executable path contains characters unsupported in a systemd unit");
    }
    // The daemon's output goes to files, the same two the launchd job and the cron rung already
    // write. Relying on the journal looked equivalent and is not: a host with no persistent
    // journal — Rocky Linux 10 ships without `/var/log/journal` — captures a user unit's stdout
    // nowhere at all, so `journalctl --user -u ciao` returns "No entries" for a daemon that has
    // been running and logging for hours. Diagnosing anything then means having predicted the
    // need in advance, which is exactly when nobody has.
    let stdout = unit_path_value(stdout_log)?;
    let stderr = unit_path_value(stderr_log)?;
    Ok(format!(
        r#"# Generated by `ciao setup`. Do not edit; rerun `ciao setup --yes` to regenerate.
[Unit]
Description=Ciao host daemon

[Service]
Type=exec
ExecStart="{text}" daemon
Restart=on-failure
RestartSec=2
KillMode=process
TimeoutStopSec=10
RuntimeDirectory=ciao
RuntimeDirectoryMode=0700
StandardOutput=append:{stdout}
StandardError=append:{stderr}

[Install]
WantedBy=default.target
"#
    ))
}

/// A path safe to interpolate into a unit directive. `append:` takes the rest of the line
/// verbatim, so a newline would forge a directive and `%` is systemd's specifier escape.
fn unit_path_value(path: &Path) -> Result<&str> {
    if !path.is_absolute() {
        bail!("daemon log path must be absolute");
    }
    let Some(text) = path.to_str() else {
        bail!("daemon log path must be valid UTF-8");
    };
    if text.bytes().any(|byte| matches!(byte, b'\n' | b'%')) {
        bail!("daemon log path contains characters unsupported in a systemd unit");
    }
    Ok(text)
}

/// Spec 004 §8.2: a globally `degraded` user manager is not itself failure; readiness is judged
/// from Ciao's own unit plus authenticated local status.
pub fn user_manager_state_supported(state: &str) -> bool {
    matches!(
        state.trim(),
        "running" | "degraded" | "starting" | "initializing" | "maintenance"
    )
}

pub fn ciao_unit_active(is_active_stdout: &str) -> bool {
    is_active_stdout.trim() == "active"
}

/// What `systemctl --user is-system-running` tells us about this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserManager {
    /// systemd is present and the per-user manager is usable.
    Ready,
    /// systemd is present but this session has no user bus. An operator can fix this;
    /// it is not the same as an unsupported platform and must not share its message.
    NoUserBus,
    /// No systemd at all, or a manager state Ciao does not support.
    Unsupported,
}

/// Spec 004 §8.2.1 asks for categorical detection. Splitting "no systemd" from "no user bus"
/// keeps a remediable environment out of the terminal unsupported path. Pure so it is testable
/// off Linux; `spawned` is whether the `systemctl` process itself ran at all.
pub fn classify_user_manager(spawned: bool, state: &str) -> UserManager {
    if !spawned {
        return UserManager::Unsupported;
    }
    match state.trim() {
        "" => UserManager::NoUserBus,
        state if user_manager_state_supported(state) => UserManager::Ready,
        _ => UserManager::Unsupported,
    }
}

/// Parses `loginctl show-user --property=Linger --value` output. Detection only — enabling
/// lingering is always an explicit operator action, never a silent privileged call.
pub fn parse_linger(output: &str) -> LingerStatus {
    match output.trim() {
        "yes" => LingerStatus::Enabled,
        "no" => LingerStatus::Disabled,
        _ => LingerStatus::Unknown,
    }
}

/// Both automatic rungs are unavailable, so setup can still explain foreground use.
#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct NoSupervisor(String);

#[cfg(target_os = "linux")]
fn install_linux_service(paths: &CiaoPaths, executable: &Path) -> Result<InstalledService> {
    paths.ensure_layout()?;
    let transaction = fs::File::open(&paths.run_dir)?;
    transaction
        .try_lock()
        .context("another Ciao service installation is in progress")?;
    let manager = user_manager();
    let (mut supervisor, linger) = selected_linux_supervisor(manager);
    if matches!(supervisor, Supervisor::CronReboot { .. }) {
        // Try the boot task before retiring any existing service. If cron is
        // unavailable, the login-only systemd rung is still an option.
        if let Err(error) = install_cron_entry(paths, executable) {
            if manager != UserManager::Ready {
                return Err(NoSupervisor(format!(
                    "{}; boot task unavailable: {error:#}",
                    no_user_bus_reason()
                ))
                .into());
            }
            supervisor = Supervisor::SystemdUser { linger };
        }
    }
    if matches!(supervisor, Supervisor::SystemdUser { .. }) {
        let unit = systemd_unit(executable, &paths.stdout_log, &paths.stderr_log)?;
        atomic_write_private(&paths.service_file, unit.as_bytes())?;
        run_systemctl(&["--user", "daemon-reload"], paths)?;
        remove_cron_entry()?;
        run_systemctl(&["--user", "stop", SYSTEMD_UNIT_NAME], paths)?;
    } else if paths.service_file.exists() {
        if manager == UserManager::Ready {
            let disabled = run_systemctl(&["--user", "disable", "--now", SYSTEMD_UNIT_NAME], paths);
            // Losing the last login can take the manager away between the probe
            // and disable. A reachable manager's error must still propagate.
            if let Err(err) = disabled
                && user_manager() == UserManager::Ready
            {
                return Err(err);
            }
        }
        disable_boot_link(paths)?;
    }
    // A stopped unit cannot respawn while we retire cron or unlinked legacy listeners.
    linux_process::stop(paths)?;
    let pid = match supervisor {
        Supervisor::SystemdUser { .. } => {
            run_systemctl(&["--user", "enable", "--now", SYSTEMD_UNIT_NAME], paths)?;
            systemd_main_pid()?.context("the Ciao user unit did not start a main process")?
        }
        Supervisor::CronReboot { .. } => start_cron_daemon(paths, executable)?,
        Supervisor::Launchd => unreachable!("launchd is not a Linux rung"),
    };
    Ok(InstalledService {
        supervisor,
        expected_pid: Some(pid),
        _transaction: Some(transaction),
    })
}

#[cfg(target_os = "linux")]
fn selected_linux_supervisor(manager: UserManager) -> (Supervisor, LingerStatus) {
    let linger = if manager == UserManager::Ready {
        detect_linger()
    } else {
        LingerStatus::Unknown
    };
    (preferred_linux_rung(manager, linger), linger)
}

#[cfg(target_os = "linux")]
fn user_manager() -> UserManager {
    let probe = systemctl_user(&["--user", "is-system-running"]).output();
    let state = match &probe {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        Err(_) => String::new(),
    };
    classify_user_manager(probe.is_ok(), &state)
}

#[cfg(target_os = "linux")]
fn disable_boot_link(paths: &CiaoPaths) -> Result<()> {
    // `systemctl --user disable` needs a bus on Debian even with --no-reload.
    // Our unit has exactly one WantedBy target. Remove only its own enable link.
    let link = paths
        .service_dir
        .join("default.target.wants")
        .join(SYSTEMD_UNIT_NAME);
    match fs::read_link(&link) {
        Ok(target) => {
            let parent = link.parent().expect("unit enable link has a parent");
            if fs::canonicalize(parent.join(target))? != fs::canonicalize(&paths.service_file)? {
                bail!(
                    "refusing to disable an unrelated unit at {}",
                    link.display()
                );
            }
            fs::remove_file(link)?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("inspect the Ciao user unit enable link"),
    }
    Ok(())
}

/// Reads the operator's crontab. `crontab -l` exits non-zero when the user simply has none,
/// which is an empty crontab rather than an error.
#[cfg(target_os = "linux")]
fn read_crontab() -> Result<String> {
    let output = Command::new("crontab")
        .arg("-l")
        .env("LC_ALL", "C")
        .output()
        .context("run `crontab -l` (is cron installed?)")?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("not allowed to use this program") {
        return Err(
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, stderr.trim()).into(),
        );
    }
    if stderr.contains("no crontab") {
        Ok(String::new())
    } else {
        bail!("`crontab -l` failed: {}", stderr.trim());
    }
}

#[cfg(target_os = "linux")]
fn write_crontab(contents: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("run `crontab -`")?;
    child
        .stdin
        .take()
        .context("crontab stdin")?
        .write_all(contents.as_bytes())
        .context("write the new crontab")?;
    let output = child.wait_with_output().context("wait for `crontab -`")?;
    if !output.status.success() {
        bail!(
            "`crontab -` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn retire_legacy_on_start(paths: &CiaoPaths) -> Result<()> {
    let legacy = linux_process::holders(paths)?;
    if !legacy.is_empty() {
        // A pre-lock updater can install this binary using its old service
        // installer. Only the confirmed unit can complete that pending handoff.
        if systemd_main_pid().ok().flatten() == i32::try_from(std::process::id()).ok()
            && fs::read_to_string("/proc/self/cgroup")?
                .lines()
                .any(|line| line.ends_with("/ciao.service"))
        {
            remove_cron_entry()?;
            return linux_process::stop_holders(legacy);
        }
        bail!("another Ciao daemon owns this instance; run `ciao setup` to repair it");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn systemd_main_pid() -> Result<Option<i32>> {
    let output = systemctl_user(&[
        "--user",
        "show",
        "--property=MainPID",
        "--value",
        SYSTEMD_UNIT_NAME,
    ])
    .output()?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid > 1))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceProblem {
    MultipleDaemons,
    MissingControlSocket,
}

impl ServiceProblem {
    pub fn description(self) -> &'static str {
        match self {
            Self::MultipleDaemons => "multiple Ciao daemons are running for this host",
            Self::MissingControlSocket => {
                "ciao.service is active but the control socket is missing"
            }
        }
    }
}

pub fn service_problem(paths: &CiaoPaths) -> Result<Option<ServiceProblem>> {
    #[cfg(target_os = "linux")]
    {
        if linux_process::holders(paths)?.len() > 1 {
            return Ok(Some(ServiceProblem::MultipleDaemons));
        }
        if !paths.socket_file.try_exists()?
            && systemctl_user(&["--user", "is-active", SYSTEMD_UNIT_NAME])
                .output()
                .is_ok_and(|output| ciao_unit_active(&String::from_utf8_lossy(&output.stdout)))
        {
            return Ok(Some(ServiceProblem::MissingControlSocket));
        }
    }
    let _ = paths;
    Ok(None)
}

/// A current release may still have a broken service or an obsolete boot rung.
pub(crate) async fn current_release_needs_repair(
    paths: &CiaoPaths,
    reachable: bool,
) -> Result<bool> {
    if service_problem(paths)?.is_some() {
        return Ok(true);
    }
    #[cfg(target_os = "linux")]
    if paths.credentials_file.is_file() {
        let manager = user_manager();
        let (preferred, _) = selected_linux_supervisor(manager);
        let main_pid = if manager == UserManager::Ready {
            systemd_main_pid()?
        } else {
            None
        };
        let cron = read_crontab()
            .ok()
            .map(|table| table.lines().any(|line| line.trim() == CRON_BEGIN));
        if matches!(preferred, Supervisor::CronReboot { .. }) {
            if let Some(has_entry) = cron {
                return Ok(!reachable || main_pid.is_some() || !has_entry);
            }
            // No usable cron: a reachable manager can still provide a login-only unit.
            if manager != UserManager::Ready {
                return Ok(false);
            }
        }
        return Ok(match main_pid {
            Some(pid) if reachable && cron != Some(true) => {
                crate::ipc::request_status_from(&paths.socket_file, Some(pid))
                    .await
                    .is_err()
            }
            _ => true,
        });
    }
    let _ = reachable;
    Ok(false)
}

#[cfg(target_os = "linux")]
fn remove_cron_entry() -> Result<()> {
    // A systemd-only account may have no crontab command or no permission to use it.
    let existing = match read_crontab() {
        Ok(table) => table,
        Err(err)
            if err.downcast_ref::<std::io::Error>().is_some_and(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                )
            }) =>
        {
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    if existing.lines().any(|line| line.trim() == CRON_BEGIN) {
        write_crontab(&crontab_without_ciao(&existing))?;
    }
    Ok(())
}

/// Installs the `@reboot` boot task. The operator's existing entries are read, our managed
/// block is replaced in place, and everything else is written back untouched.
#[cfg(target_os = "linux")]
fn install_cron_entry(paths: &CiaoPaths, executable: &Path) -> Result<()> {
    paths.ensure_layout()?;
    let command = cron_command(executable, &paths.stderr_log)?;
    let existing = read_crontab()?;
    let updated = crontab_with_ciao(&existing, &command);
    // Defence in depth before a destructive write. The transform is unit-tested, but this is
    // the operator's crontab: a regression here is unrecoverable and may be years of entries.
    // Refuse rather than write anything that dropped a line Ciao did not put there.
    for line in crontab_without_ciao(&existing).lines() {
        if !updated.lines().any(|candidate| candidate == line) {
            bail!("refusing to write a crontab that would drop an existing entry: {line:?}");
        }
    }
    write_crontab(&updated)
}

#[cfg(target_os = "linux")]
fn start_cron_daemon(paths: &CiaoPaths, executable: &Path) -> Result<i32> {
    // The boot task only fires at boot, so start the daemon now: nobody should have to reboot
    // to reach a host they just set up. This is a plain start of the service cron owns from
    // here on, the same thing `systemctl start` does after a unit is written — Ciao still
    // supervises nothing itself.
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.stderr_log)
        .with_context(|| format!("open {}", paths.stderr_log.display()))?;
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(executable);
    command
        .arg("daemon")
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone().context("clone the daemon log handle")?)
        .stderr(log);
    // Detach into a new session and process group so Ctrl-C (SIGINT) during the setup/pair QR
    // wait or SSH disconnect (SIGHUP) does not kill the cron-started daemon.
    // SAFETY: `setsid` is async-signal-safe per POSIX.1-2008 and allocates nothing.
    unsafe {
        command.pre_exec(|| {
            nix::unistd::setsid().map_err(std::io::Error::from)?;
            Ok(())
        });
    }
    let child = command.spawn().context("start the Ciao daemon")?;
    Ok(i32::try_from(child.id())?)
}

/// `systemctl --user` needs `XDG_RUNTIME_DIR` to locate the user manager. A process outside a
/// login session has none — anything under cron, and any multiplexer pane descending from it —
/// even when the manager itself is running and healthy. Supplying the directory when it exists
/// and belongs to us turns a whole class of "unsupported host" into an ordinary install.
///
/// Verified on Debian 12: with the directory set, `systemctl --user` enables, starts, and
/// restarts units through `/run/user/<uid>/systemd/private` with `dbus-user-session` absent.
/// The session bus is not required for any of it.
#[cfg(target_os = "linux")]
fn effective_runtime_dir() -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    if let Some(existing) = std::env::var_os("XDG_RUNTIME_DIR") {
        let path = PathBuf::from(existing);
        if path.is_absolute() {
            return Some(path);
        }
    }
    let uid = nix::unistd::Uid::effective().as_raw();
    let path = PathBuf::from(format!("/run/user/{uid}"));
    // Only adopt it when it is ours. A runtime directory owned by somebody else is not our
    // session, and pointing systemctl at it would be both wrong and rude.
    let metadata = fs::metadata(&path).ok()?;
    (metadata.uid() == uid).then_some(path)
}

/// Every `systemctl --user` call goes through here so none of them can forget the runtime
/// directory and reintroduce the false "no user manager" verdict.
#[cfg(target_os = "linux")]
fn systemctl_user(args: &[&str]) -> Command {
    let mut command = Command::new("systemctl");
    command.args(args);
    if let Some(dir) = effective_runtime_dir() {
        command.env("XDG_RUNTIME_DIR", dir);
    }
    command
}

#[cfg(target_os = "linux")]
fn effective_user_name() -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .ok()
        .flatten()
        .map(|user| user.name)
}

/// Why `systemctl --user` could not reach a manager, with the remedy that actually applies.
/// These three causes need three different fixes and are routinely confused for each other:
/// a process outside any login session has no runtime directory at all; Debian and Ubuntu
/// ship the per-user session bus in `dbus-user-session`, which headless installs omit; and
/// lingering is a separate concern that only affects persistence.
#[cfg(target_os = "linux")]
fn no_user_bus_reason() -> String {
    match effective_runtime_dir() {
        None => "no per-user systemd manager is reachable: this account has no runtime \
                 directory, so no user session has been established for it"
            .to_owned(),
        Some(dir) => format!(
            "a runtime directory exists at {} but the per-user systemd manager did not answer",
            dir.display()
        ),
    }
}

#[cfg(target_os = "linux")]
fn detect_linger() -> LingerStatus {
    let Some(user) = effective_user_name() else {
        return LingerStatus::Unknown;
    };
    match Command::new("loginctl")
        .args(["show-user", "--property=Linger", "--value", &user])
        .output()
    {
        Ok(output) if output.status.success() => {
            parse_linger(&String::from_utf8_lossy(&output.stdout))
        }
        _ => LingerStatus::Unknown,
    }
}

#[cfg(target_os = "linux")]
fn run_systemctl(args: &[&str], paths: &CiaoPaths) -> Result<()> {
    let output = systemctl_user(args).output().context("execute systemctl")?;
    require_success("systemctl", &output, paths)
}

/// Stops and removes the per-user service for the explicit full reset (Spec 004 §9.3).
/// Missing services/files are fine; this must be idempotent.
pub fn uninstall_service(paths: &CiaoPaths) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let uid = nix::unistd::Uid::effective().as_raw();
        for label in [LAUNCH_AGENT_LABEL, LEGACY_LAUNCH_AGENT_LABEL] {
            let service = format!("gui/{uid}/{label}");
            // A not-loaded service returns an error; that is the already-stopped case.
            let _ = Command::new("launchctl")
                .args(["bootout", service.as_str()])
                .output();
        }
        let legacy_file = legacy_launch_agent_file(paths);
        match fs::remove_file(&legacy_file) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("remove {}", legacy_file.display()));
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let _ = systemctl_user(&["--user", "disable", "--now", SYSTEMD_UNIT_NAME]).output();
        // Reset must not leave a boot task pointing at a host that no longer exists. A missing
        // crontab is the already-clean case; only write back when we actually removed a block,
        // so a reset never rewrites a crontab it had no reason to touch.
        remove_cron_entry()?;
        linux_process::stop(paths)?;
    }
    match fs::remove_file(&paths.service_file) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("remove {}", paths.service_file.display()));
        }
    }
    #[cfg(target_os = "linux")]
    {
        let _ = systemctl_user(&["--user", "daemon-reload"]).output();
    }
    Ok(())
}

fn require_success(action: &str, output: &Output, paths: &CiaoPaths) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "{action} failed (status {}): {}\nThe host identity was preserved. Inspect '{}' and {}, then rerun `ciao setup --yes`.",
        output.status,
        stderr.trim(),
        paths.service_file.display(),
        paths.log_hint()
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn current_executable() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("locate the installed ciao executable")?;
    if !executable.is_absolute() {
        bail!("current executable path is not absolute");
    }
    Ok(executable)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn plist_has_expected_safe_arguments_and_paths() {
        let temp = tempdir().unwrap();
        let paths = CiaoPaths::for_home(temp.path().join("home & user"));
        let executable = Path::new("/Users/test/bin/ciao");
        let plist = launch_agent_plist(&paths, executable).unwrap();
        assert!(plist.contains("<string>/Users/test/bin/ciao</string>"));
        assert!(plist.contains("<string>daemon</string>"));
        assert!(plist.contains(LAUNCH_AGENT_LABEL));
        assert!(!plist.contains(LEGACY_LAUNCH_AGENT_LABEL));
        assert_eq!(
            legacy_launch_agent_file(&paths)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            "com.bojanstef.ciao.daemon.plist"
        );
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        // Not Background and not Adaptive: both leave the job at PRI 4, and every child the
        // daemon spawns inherits it — measured at 40x on the slash-command probe. The comment
        // beside the key in `launch_agent_plist` carries the numbers. Asserting the two rejected
        // values by name is the point, because both read as reasonable for a background daemon
        // and Adaptive in particular looks like a safe middle setting it is not.
        assert!(plist.contains("<key>ProcessType</key>"));
        assert!(plist.contains("<string>Standard</string>"));
        assert!(!plist.contains("<string>Background</string>"));
        assert!(!plist.contains("<string>Adaptive</string>"));
        assert!(plist.contains("home &amp; user"));
        assert!(plist.contains("daemon.stdout.log"));
        assert!(plist.contains("daemon.stderr.log"));
        for secret_word in [
            "secret_key",
            "capability",
            "relay token",
            "credentials.json",
        ] {
            assert!(!plist.contains(secret_word));
        }
    }

    #[test]
    fn systemd_unit_is_deterministic_fixed_argv_without_shell() {
        let out_log = Path::new("/home/alpha/.local/state/ciao/logs/daemon.stdout.log");
        let err_log = Path::new("/home/alpha/.local/state/ciao/logs/daemon.stderr.log");
        let (out, err) = (out_log, err_log);
        let unit = systemd_unit(Path::new("/home/alpha/.local/bin/ciao"), out, err).unwrap();
        assert_eq!(
            unit,
            systemd_unit(Path::new("/home/alpha/.local/bin/ciao"), out, err).unwrap()
        );
        assert!(unit.contains("ExecStart=\"/home/alpha/.local/bin/ciao\" daemon\n"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("KillMode=process"));
        assert!(unit.contains("RuntimeDirectory=ciao"));
        assert!(unit.contains("RuntimeDirectoryMode=0700"));
        assert!(unit.contains("WantedBy=default.target"));
        // Output has to reach a file. A host with no persistent journal captures a user unit's
        // stdout nowhere, which is how a daemon logging every registration produced
        // `journalctl --user -u ciao` → "No entries" on Rocky Linux 10.
        assert!(unit.contains(
            "StandardOutput=append:/home/alpha/.local/state/ciao/logs/daemon.stdout.log\n"
        ));
        assert!(unit.contains(
            "StandardError=append:/home/alpha/.local/state/ciao/logs/daemon.stderr.log\n"
        ));
        // A newline would forge a directive; `%` is systemd's specifier escape.
        assert!(
            systemd_unit(
                Path::new("/home/alpha/ciao"),
                Path::new("/l/a\nExecStart=/x"),
                err
            )
            .is_err()
        );
        assert!(systemd_unit(Path::new("/home/alpha/ciao"), out, Path::new("/l/%h.log")).is_err());
        assert!(systemd_unit(Path::new("/home/alpha/ciao"), Path::new("rel.log"), err).is_err());
        for forbidden in [
            "sh -c",
            "/bin/sh",
            "ExecStartPre",
            "Environment=",
            "PrivateTmp",
            "ProtectHome",
            "$",
        ] {
            assert!(
                !unit.contains(forbidden),
                "unit must not contain {forbidden}"
            );
        }

        assert!(systemd_unit(Path::new("relative/ciao"), out, err).is_err());
        assert!(systemd_unit(Path::new("/home/a\"b/ciao"), out, err).is_err());
        assert!(systemd_unit(Path::new("/home/a%h/ciao"), out, err).is_err());
        assert!(systemd_unit(Path::new("/home/a\\b/ciao"), out, err).is_err());
    }

    #[test]
    fn user_manager_and_unit_classification_accepts_degraded_globally_only() {
        assert!(user_manager_state_supported("running"));
        assert!(user_manager_state_supported("degraded\n"));
        assert!(!user_manager_state_supported("offline"));
        assert!(!user_manager_state_supported("unknown"));
        assert!(!user_manager_state_supported(""));

        assert!(ciao_unit_active("active\n"));
        assert!(!ciao_unit_active("failed\n"));
        assert!(!ciao_unit_active("inactive"));
        assert!(!ciao_unit_active(""));
    }

    /// Synthetic crontab with the same preservation cases as the original regression:
    /// unrelated boot work, scheduled backup work, and a deceptively Ciao-like filename.
    const HERDR: &str = "\
# m h  dom mon dow   command
MAILTO=\"\"

@reboot sleep 7 && SHELL=/bin/bash /bin/bash -lc \"herdr server\"
*/11 * * * * /opt/example/backup.sh --quiet  # keep
@daily /home/example/bin/ciao-ish-but-not-ours.sh
";

    fn ciao_line() -> String {
        cron_command(
            Path::new("/home/example/.local/bin/ciao"),
            Path::new("/home/example/.local/state/ciao/logs/daemon.stderr.log"),
        )
        .unwrap()
    }

    #[test]
    fn a_user_unit_outranks_a_boot_task_only_when_lingering_is_enabled() {
        // The case that motivated this ordering: a healthy user manager, lingering off. The
        // unit would start at login and die at logout, so it cannot keep a host reachable.
        assert_eq!(
            preferred_linux_rung(UserManager::Ready, LingerStatus::Disabled),
            Supervisor::CronReboot {
                reason: CronReason::LingeringDisabled
            },
            "without lingering a user unit dies at logout; a boot task does not"
        );
        assert_eq!(
            preferred_linux_rung(UserManager::Ready, LingerStatus::Unknown),
            Supervisor::CronReboot {
                reason: CronReason::LingeringDisabled
            },
            "unconfirmed lingering must not be treated as persistence"
        );
        assert_eq!(
            preferred_linux_rung(UserManager::Ready, LingerStatus::Enabled),
            Supervisor::SystemdUser {
                linger: LingerStatus::Enabled
            },
            "with lingering the unit is strictly better: it also restarts on crash"
        );
        // No manager at all: nothing to prefer.
        for linger in [
            LingerStatus::Enabled,
            LingerStatus::Disabled,
            LingerStatus::Unknown,
        ] {
            assert_eq!(
                preferred_linux_rung(UserManager::NoUserBus, linger),
                Supervisor::CronReboot {
                    reason: CronReason::NoUserManager
                }
            );
            assert_eq!(
                preferred_linux_rung(UserManager::Unsupported, linger),
                Supervisor::CronReboot {
                    reason: CronReason::NoUserManager
                }
            );
        }
    }

    #[test]
    fn installing_the_boot_task_preserves_every_existing_entry() {
        let updated = crontab_with_ciao(HERDR, &ciao_line());
        for line in HERDR.lines() {
            assert!(
                updated.contains(line),
                "install dropped an operator line: {line:?}"
            );
        }
        assert!(updated.contains("@reboot \"/home/example/.local/bin/ciao\" daemon"));
        assert!(updated.starts_with(HERDR), "existing entries must stay put");
    }

    #[test]
    fn removing_the_boot_task_restores_the_crontab_byte_for_byte() {
        let updated = crontab_with_ciao(HERDR, &ciao_line());
        assert_eq!(
            crontab_without_ciao(&updated),
            HERDR,
            "reset must leave the operator's crontab exactly as it found it"
        );
    }

    #[test]
    fn installing_twice_is_idempotent() {
        let once = crontab_with_ciao(HERDR, &ciao_line());
        let twice = crontab_with_ciao(&once, &ciao_line());
        assert_eq!(once, twice, "a second install must not duplicate the block");
        assert_eq!(twice.matches(CRON_BEGIN).count(), 1);
    }

    #[test]
    fn reinstalling_replaces_the_command_without_disturbing_neighbours() {
        let old = crontab_with_ciao(HERDR, "\"/old/path/ciao\" daemon");
        let new = crontab_with_ciao(&old, &ciao_line());
        assert!(
            !new.contains("/old/path/ciao"),
            "stale command must be gone"
        );
        assert!(new.contains("/home/example/.local/bin/ciao"));
        assert_eq!(crontab_without_ciao(&new), HERDR);
    }

    #[test]
    fn an_unterminated_block_never_eats_the_entries_below_it() {
        // A crash between the two marker writes must not cost the operator their crontab.
        let damaged = format!("{CRON_BEGIN}\n@reboot \"/x\" daemon\n{HERDR}");
        let cleaned = crontab_without_ciao(&damaged);
        assert!(
            cleaned.contains("herdr server"),
            "an unmatched BEGIN must drop only itself, not the rest of the file"
        );
        assert!(cleaned.contains("backup.sh"));
        assert!(!cleaned.contains(CRON_BEGIN));
    }

    #[test]
    fn a_stray_end_marker_is_left_alone() {
        let odd = format!("{HERDR}{CRON_END}\n");
        assert_eq!(crontab_without_ciao(&odd), odd);
    }

    #[test]
    fn lines_that_merely_mention_ciao_are_not_ours_to_remove() {
        assert!(
            crontab_without_ciao(HERDR).contains("ciao-ish-but-not-ours.sh"),
            "only our exact markers delimit our block"
        );
        assert_eq!(crontab_without_ciao(HERDR), HERDR);
    }

    #[test]
    fn a_crontab_without_a_trailing_newline_stays_well_formed() {
        let no_newline = "@reboot /bin/true";
        let updated = crontab_with_ciao(no_newline, &ciao_line());
        assert!(
            updated.contains("@reboot /bin/true\n"),
            "must not join lines"
        );
        assert!(updated.ends_with('\n'), "cron requires a final newline");
        assert_eq!(crontab_without_ciao(&updated), "@reboot /bin/true\n");
    }

    #[test]
    fn an_empty_crontab_gains_only_our_block() {
        let updated = crontab_with_ciao("", &ciao_line());
        assert!(updated.starts_with(CRON_BEGIN));
        assert!(updated.ends_with(&format!("{CRON_END}\n")));
        assert_eq!(crontab_without_ciao(&updated), "");
    }

    #[test]
    fn cron_fields_reject_what_would_split_or_escape_the_entry() {
        let log = Path::new("/var/log/ciao.log");
        // `%` becomes a newline in a crontab command: this would inject a second entry.
        assert!(cron_command(Path::new("/home/a%b/ciao"), log).is_err());
        // A quote would terminate ours early and leave the rest as bare shell words.
        assert!(cron_command(Path::new("/home/a\"b/ciao"), log).is_err());
        assert!(cron_command(Path::new("relative/ciao"), log).is_err());
        assert!(cron_command(Path::new("/home/example/.local/bin/ciao"), log).is_ok());
        // A hostile log path must be rejected on the same grounds as the executable.
        assert!(cron_command(Path::new("/bin/ciao"), Path::new("/log%x")).is_err());
    }

    #[test]
    fn the_command_redirects_so_cron_does_not_mail_the_operator_every_boot() {
        let line = ciao_line();
        assert!(
            line.contains(">>"),
            "output must go to the log, not to mail"
        );
        assert!(line.contains("2>&1"));
    }

    #[test]
    fn user_manager_classification_separates_no_bus_from_unsupported() {
        // systemctl never ran: no systemd here at all.
        assert_eq!(
            classify_user_manager(false, ""),
            UserManager::Unsupported,
            "a missing systemctl is an unsupported platform"
        );
        // systemctl ran but printed nothing: present, but no user bus in this session.
        assert_eq!(
            classify_user_manager(true, ""),
            UserManager::NoUserBus,
            "an empty probe must stay remediable, not terminal"
        );
        assert_eq!(classify_user_manager(true, "   \n"), UserManager::NoUserBus);
        // A real state decides on its own merits.
        assert_eq!(classify_user_manager(true, "running"), UserManager::Ready);
        assert_eq!(classify_user_manager(true, "degraded"), UserManager::Ready);
        assert_eq!(
            classify_user_manager(true, "offline"),
            UserManager::Unsupported
        );
    }

    #[test]
    fn linger_detection_is_categorical() {
        assert_eq!(parse_linger("yes\n"), LingerStatus::Enabled);
        assert_eq!(parse_linger("no\n"), LingerStatus::Disabled);
        assert_eq!(parse_linger("garbage"), LingerStatus::Unknown);
        assert_eq!(parse_linger(""), LingerStatus::Unknown);
    }
}
