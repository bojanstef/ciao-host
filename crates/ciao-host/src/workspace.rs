//! Host-side workspace provider discovery and execution for Spec 003.
//!
//! Every provider invocation here is a fixed argv resolved from a fixed directory list. No code
//! path interpolates client bytes into a shell string, searches `PATH`, or honors provider
//! configuration from the environment. Provider stdout/stderr are parsed, bounded, and discarded;
//! they are never forwarded to the client or logged.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use serde_json::Value;
use tokio::{
    io::AsyncReadExt,
    process::Command,
    time::{Instant, timeout, timeout_at},
};

use crate::{
    host_protocol::{
        AgentTabIndex, HerdrProviderSnapshot, HerdrSessionEntry, HostProtocolError,
        MAX_PROVIDER_VERSION_BYTES, MAX_SESSIONS_PER_PROVIDER, MAX_TAB_LABEL_BYTES,
        MAX_TABS_PER_SESSION, PROVIDER_STATE_AVAILABLE, PROVIDER_STATE_ERROR,
        PROVIDER_STATE_NOT_INSTALLED, PROVIDER_STATE_UNSUPPORTED_VERSION, ProviderKind,
        SessionTabEntry, TerminalTarget, TmuxProviderSnapshot, TmuxSessionEntry,
        WorkspaceProviders, WorkspaceSnapshotResult, valid_session_name, valid_tab_id,
        valid_tab_status,
    },
    pty::{apply_clean_process_environment, is_absolute_executable},
};

/// Spec 003 §5.1: the only directories a provider binary may resolve from. The Linux list is
/// bounded to the grounded Debian tmux (apt) and per-user Herdr installations (Spec 004 §8.3);
/// arbitrary PATH/shim lookup stays forbidden on both platforms.
#[cfg(target_os = "macos")]
pub(crate) const PROVIDER_BINARY_DIRS: &[&str] =
    &["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"];
#[cfg(not(target_os = "macos"))]
pub(crate) const PROVIDER_BINARY_DIRS: &[&str] = &["/usr/local/bin", "/usr/bin"];

/// Home-relative provider directories, joined to the effective account home. Only Linux adds
/// the grounded per-user install locations.
#[cfg(target_os = "linux")]
const PROVIDER_HOME_RELATIVE_DIRS: &[&str] = &[".local/bin", ".cargo/bin"];
#[cfg(not(target_os = "linux"))]
const PROVIDER_HOME_RELATIVE_DIRS: &[&str] = &[];

pub(crate) const SNAPSHOT_BUDGET: Duration = Duration::from_secs(5);
const PROVIDER_EXEC_TIMEOUT: Duration = Duration::from_secs(3);
const PROVIDER_STDOUT_CAP: usize = 64 * 1024;
const PROVIDER_STDERR_CAP: usize = 8 * 1024;
const HERDR_JSON_MAX_BYTES: usize = 64 * 1024;
/// Maximum container nesting for the lenient Herdr document: object → array → object → object.
const HERDR_JSON_MAX_DEPTH: usize = 4;
const TMUX_MIN_MAJOR: u64 = 3;
const HERDR_MIN_MAJOR_MINOR: (u64, u64) = (0, 7);
const UNIT_SEPARATOR: char = '\u{1f}';
/// How tmux 3.4 writes 0x1F when it has no UTF-8 locale: the four literal characters `\037`.
const UNIT_SEPARATOR_ESCAPE: &str = "\\037";

/// Forces tmux to treat the terminal as UTF-8 rather than inferring it from a locale Ciao's
/// daemon does not have. Deliberately not applied to the snapshot commands: their output is
/// parsed, and `parse_tmux_list` already handles the non-UTF-8 separator that tmux emits.
const TMUX_FORCE_UTF8: &str = "-u";

/// tmux list format joining name, attached count, window count, and creation time on 0x1F.
pub(crate) const TMUX_LIST_FORMAT: &str =
    "#{session_name}\u{1f}#{session_attached}\u{1f}#{session_windows}\u{1f}#{session_created}";

/// Spec 021 §4.1: space-separated on purpose, sidestepping the 0x1F locale swamp above. Every
/// fixed field is space-free — window ids are `@N`, active is 0/1, indexes are digits, and a
/// session name with a space already fails §5.4 and is omitted — so the free-text window name
/// is safely "the rest of the line" and needs no separator at all.
pub(crate) const TMUX_WINDOW_LIST_FORMAT: &str =
    "#{window_id} #{window_active} #{window_index} #{session_name} #{window_name}";

/// Spec 021 §4.2: how many running herdr sessions get a tab query per snapshot. Beyond this,
/// sessions list without tabs rather than stretching the snapshot budget.
const MAX_HERDR_TAB_QUERIES: usize = 8;

#[derive(Debug, Clone)]
pub(crate) struct WorkspaceConfig {
    binary_dirs: Vec<PathBuf>,
}

impl WorkspaceConfig {
    /// The reviewed fixed directory list for this platform. `home` is the effective account
    /// home from the platform account record, never an environment value.
    pub(crate) fn for_home(home: &Path) -> Self {
        let mut binary_dirs: Vec<PathBuf> =
            PROVIDER_BINARY_DIRS.iter().map(PathBuf::from).collect();
        binary_dirs.extend(
            PROVIDER_HOME_RELATIVE_DIRS
                .iter()
                .map(|relative| home.join(relative)),
        );
        Self { binary_dirs }
    }
    #[cfg(test)]
    pub(crate) fn with_binary_dirs(binary_dirs: Vec<PathBuf>) -> Self {
        Self { binary_dirs }
    }

    pub(crate) fn resolve(&self, kind: ProviderKind) -> Option<PathBuf> {
        self.binary_dirs
            .iter()
            .map(|directory| directory.join(kind.wire()))
            .find(|candidate| is_absolute_executable(candidate))
    }
}

/// Builds the exact fixed argv for a session terminal target. The session name is re-validated
/// here so no argv can be constructed from an unvalidated name even if a caller misses a check.
pub(crate) fn target_command(
    target: TerminalTarget,
    session: &str,
    binary: &Path,
    home: &Path,
) -> Result<(PathBuf, Vec<OsString>), HostProtocolError> {
    if !valid_session_name(session) {
        return Err(HostProtocolError::InvalidTarget);
    }
    let args: Vec<OsString> = match target {
        TerminalTarget::TmuxAttach => vec![
            // Ciao's tmux client has no UTF-8 locale to infer one from: the daemon runs under
            // launchd, which supplies no LANG, and the environment allowlist can only pass on
            // a variable that exists. Without this tmux substitutes `_` for every non-ASCII
            // character it draws, and miscomputes character widths well enough to lose whole
            // columns of a TUI's layout. Herdr sessions were never affected, which is what
            // made this look like a font problem.
            TMUX_FORCE_UTF8.into(),
            "attach-session".into(),
            "-t".into(),
            // The `=` prefix forces an exact-name match instead of tmux prefix matching.
            format!("={session}").into(),
        ],
        TerminalTarget::TmuxCreate => vec![
            TMUX_FORCE_UTF8.into(),
            "new-session".into(),
            "-A".into(),
            "-s".into(),
            session.into(),
            "-c".into(),
            home.as_os_str().to_owned(),
        ],
        TerminalTarget::HerdrAttach => vec!["session".into(), "attach".into(), session.into()],
        TerminalTarget::HerdrCreate => vec!["--session".into(), session.into()],
        TerminalTarget::Shell | TerminalTarget::AgentRoute => {
            return Err(HostProtocolError::UnsupportedTarget);
        }
    };
    Ok((binary.to_owned(), args))
}

/// Everything the handback argv is built from. Absolute paths throughout: the daemon's
/// launchd `PATH` is `/usr/bin:/bin:/usr/sbin:/sbin`, so nothing here may be resolved by name.
pub(crate) struct HandbackRequest<'a> {
    pub(crate) session: &'a str,
    pub(crate) workspace: &'a str,
    /// The `PATH` recorded at install time, so Claude's own tools work in the handed-back
    /// terminal. It travels in the argv rather than in our spawn environment because
    /// `new-session` may be served by a tmux server we did not start and whose environment
    /// we therefore do not control.
    pub(crate) tool_path: &'a str,
    /// The pinned Claude CLI, which is a native executable and is exec'd directly. The managed
    /// worker's Node interpreter is not involved: Node runs the worker's own `.mjs` entrypoint
    /// and the CLI path is handed to the SDK, so putting an interpreter in front of it here
    /// produced a terminal that died the instant it started.
    pub(crate) cli: &'a str,
    pub(crate) vendor_session: &'a str,
}

/// `env` is used as an argv prefix, not a shell: it sets one variable for the process tmux
/// execs and nothing is ever interpreted. A shell here would mean quoting a vendor ID into a
/// command string, which is the class of bug this codebase refuses to introduce.
const HANDBACK_ENV_BINARY: &str = "/usr/bin/env";

/// How long a doomed handback gets to finish dying before its session is declared real.
/// Paid once per release, which is a rare and deliberate act; a wrong route costs far more.
const HANDBACK_SETTLE: Duration = Duration::from_millis(1500);

/// Names the session Ciao hands back. The workspace is carried so `tmux ls` is legible at the
/// moment it matters — someone looking for where their conversation went — and the opaque
/// fragment makes collision with a user's own session impossible.
pub(crate) fn handback_session_name(workspace_label: &str, session_id: &str) -> Option<String> {
    let label: String = workspace_label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .take(24)
        .collect();
    let fragment: String = session_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(12)
        .collect();
    if fragment.is_empty() {
        return None;
    }
    let name = if label.is_empty() {
        format!("ciao-{fragment}")
    } else {
        format!("ciao-{label}-{fragment}")
    };
    valid_session_name(&name).then_some(name)
}

/// Builds the exact fixed argv that creates the detached handback session.
///
/// Detached on purpose: the session has to exist whether or not anyone attaches, because the
/// point of a handback is that nobody is at the machine. `-A` is deliberately not used — it
/// would silently adopt an existing session running something else instead of failing.
pub(crate) fn handback_argv(request: &HandbackRequest<'_>) -> Option<Vec<String>> {
    if !valid_session_name(request.session) {
        return None;
    }
    // The vendor ID becomes an argv element, never a string a shell will read, but a value
    // that cannot be a session identifier is still refused rather than passed along.
    if request.vendor_session.is_empty()
        || !request
            .vendor_session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return None;
    }
    if !Path::new(request.workspace).is_absolute() || !Path::new(request.cli).is_absolute() {
        return None;
    }
    Some(vec![
        // Same reason as the attach path: the session Ciao creates here is one a phone will
        // attach, and a handed-back Claude rendered in underscores is not handed back well.
        TMUX_FORCE_UTF8.into(),
        "new-session".into(),
        "-d".into(),
        "-s".into(),
        request.session.into(),
        "-c".into(),
        request.workspace.into(),
        HANDBACK_ENV_BINARY.into(),
        format!("PATH={}", request.tool_path),
        request.cli.into(),
        "--resume".into(),
        request.vendor_session.into(),
    ])
}

/// Creates the handback session and confirms it is still there afterwards.
///
/// The confirmation is not ceremony: tmux ends a session when its last pane's process exits,
/// so a Claude that fails to start takes the session with it and `new-session` still reports
/// success. Handing back a route to a session that no longer exists is worse than admitting
/// there is no route.
///
/// It settles first because an immediate check is not the same check. A handback built with
/// the wrong argv did die, and this still reported success — the doomed process had not
/// finished failing yet. Startup failures are fast but they are not instant.
pub(crate) async fn create_handback_session(
    config: &WorkspaceConfig,
    request: &HandbackRequest<'_>,
) -> bool {
    let Some(binary) = config.resolve(ProviderKind::Tmux) else {
        return false;
    };
    let Some(argv) = handback_argv(request) else {
        return false;
    };
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    match run_bounded(&binary, &borrowed).await {
        Ok(output) if output.status_success => {}
        _ => return false,
    }
    tokio::time::sleep(HANDBACK_SETTLE).await;
    matches!(
        run_bounded(&binary, &["has-session", "-t", &format!("={}", request.session)]).await,
        Ok(output) if output.status_success
    )
}

/// Closes a handback terminal so its conversation can be taken back.
///
/// Ciao created this session and recorded its name, so it is the one terminal Ciao may end
/// without resolving an owner from process ancestry — the takeover path's harder problem does
/// not arise here. Killing it is what makes the conversation resumable again: the Claude inside
/// holds the transcript, and `managed_resume`'s foreign-owner probe would otherwise refuse the
/// take-back on the strength of a process Ciao itself started.
///
/// Best effort. A tmux that is gone, or a session already closed by the user, is the state this
/// was trying to reach; the probe that runs next is what actually decides.
pub(crate) async fn close_handback_session(config: &WorkspaceConfig, session: &str) -> bool {
    if !valid_session_name(session) {
        return false;
    }
    let Some(binary) = config.resolve(ProviderKind::Tmux) else {
        return false;
    };
    let target = format!("={session}");
    // Ask the Claude inside to exit before tearing its terminal down. Killing the session first
    // would SIGHUP it mid-write, and the transcript it is holding is the very thing the worker
    // about to resume this conversation reads — the same reason a takeover SIGTERMs the
    // terminal owner rather than killing it. Losing the last turns of a conversation to reclaim
    // it would be a worse outcome than not reclaiming it.
    if let Ok(output) =
        run_bounded(&binary, &["list-panes", "-t", &target, "-F", "#{pane_pid}"]).await
        && output.status_success
        && !output.stdout_truncated
        && let Ok(listing) = std::str::from_utf8(&output.stdout)
    {
        for pid in listing
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .take(8)
        {
            crate::process::request_exit(pid).await;
        }
    }
    matches!(
        run_bounded(&binary, &["kill-session", "-t", &target]).await,
        Ok(output) if output.status_success
    )
}

/// Which of `candidates` are tmux sessions that still exist. A terminal handed back to the
/// user is the user's to close, so a route recorded at release time is a claim with a shelf
/// life; advertising a closed one gives the phone a button that does nothing.
///
/// One `list-sessions` rather than a `has-session` per name: same answer, one process. An
/// absent tmux or a stopped server both mean nothing is live, which is the empty set.
pub(crate) async fn existing_tmux_sessions(
    config: &WorkspaceConfig,
    candidates: &[String],
) -> std::collections::HashSet<String> {
    if candidates.is_empty() {
        return std::collections::HashSet::new();
    }
    let Some(binary) = config.resolve(ProviderKind::Tmux) else {
        return std::collections::HashSet::new();
    };
    let listing = run_bounded(&binary, &["list-sessions", "-F", "#{session_name}"]).await;
    let Ok(output) = listing else {
        return std::collections::HashSet::new();
    };
    if !output.status_success {
        return std::collections::HashSet::new();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let live: std::collections::HashSet<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    candidates
        .iter()
        .filter(|candidate| live.contains(candidate.as_str()))
        .cloned()
        .collect()
}

/// `tabs` carries both decisions at once: `None` omits tab listings entirely, `Some(index)`
/// includes them annotated with the agent sessions that index names. One parameter rather than a
/// flag beside a map, so annotating tabs nobody asked for is unrepresentable.
pub(crate) async fn capture_snapshot(
    config: &WorkspaceConfig,
    tabs: Option<&AgentTabIndex>,
) -> WorkspaceSnapshotResult {
    let deadline = Instant::now() + SNAPSHOT_BUDGET;
    let tmux_config = config.clone();
    let herdr_config = config.clone();
    let tmux_agents = tabs.cloned();
    let herdr_agents = tabs.cloned();
    let mut tmux_task =
        tokio::spawn(async move { snapshot_tmux(&tmux_config, tmux_agents.as_ref()).await });
    let mut herdr_task =
        tokio::spawn(async move { snapshot_herdr(&herdr_config, herdr_agents.as_ref()).await });

    let (tmux, tmux_omitted) = match timeout_at(deadline, &mut tmux_task).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) => (error_tmux(None), 0),
        Err(_) => {
            // Budget exceeded: abort the provider task; kill_on_drop reaps any child.
            tmux_task.abort();
            (error_tmux(None), 0)
        }
    };
    let (herdr, herdr_omitted) = match timeout_at(deadline, &mut herdr_task).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) => (error_herdr(None), 0),
        Err(_) => {
            herdr_task.abort();
            (error_herdr(None), 0)
        }
    };

    WorkspaceSnapshotResult {
        v: crate::host_protocol::HOST_PROTOCOL_VERSION,
        providers: WorkspaceProviders { tmux, herdr },
        omitted_sessions: tmux_omitted.saturating_add(herdr_omitted),
    }
}

fn error_tmux(version: Option<String>) -> TmuxProviderSnapshot {
    TmuxProviderSnapshot {
        state: PROVIDER_STATE_ERROR.into(),
        version,
        sessions: None,
    }
}

fn error_herdr(version: Option<String>) -> HerdrProviderSnapshot {
    HerdrProviderSnapshot {
        state: PROVIDER_STATE_ERROR.into(),
        version,
        sessions: None,
    }
}

async fn snapshot_tmux(
    config: &WorkspaceConfig,
    tabs: Option<&AgentTabIndex>,
) -> (TmuxProviderSnapshot, u32) {
    let Some(binary) = config.resolve(ProviderKind::Tmux) else {
        return (
            TmuxProviderSnapshot {
                state: PROVIDER_STATE_NOT_INSTALLED.into(),
                version: None,
                sessions: None,
            },
            0,
        );
    };
    let version = match probe_version(&binary, &["-V"], ProviderKind::Tmux).await {
        Ok(version) => version,
        Err(()) => {
            crate::drift::note("tmux", "version_probe", "invalid", "", None);
            return (error_tmux(None), 0);
        }
    };
    if !version_meets_minimum(ProviderKind::Tmux, &version) {
        return (
            TmuxProviderSnapshot {
                state: PROVIDER_STATE_UNSUPPORTED_VERSION.into(),
                version: Some(version),
                sessions: None,
            },
            0,
        );
    }

    let listing = run_bounded(&binary, &["list-sessions", "-F", TMUX_LIST_FORMAT]).await;
    let (sessions, omitted) = match &listing {
        Ok(output) if output.status_success && !output.stdout_truncated => {
            parse_tmux_list(&output.stdout)
        }
        Ok(output)
            if !output.stderr_truncated
                && String::from_utf8_lossy(&output.stderr).contains("no server running") =>
        {
            // tmux without a running server is an empty provider, not an error.
            (Vec::new(), 0)
        }
        failure => {
            tracing::warn!(
                version = %version,
                detail = %provider_failure_detail(failure),
                "tmux list-sessions failed; reporting provider error"
            );
            return (error_tmux(Some(version)), 0);
        }
    };
    // Lines the parser refused are already counted for the snapshot; the ledger keeps the
    // running total across refreshes (Spec 017 §4.2). The cap is Ciao's own bound, not drift.
    crate::drift::note_by(
        "tmux",
        "mux_list",
        "omitted",
        "",
        Some(&version),
        u64::from(omitted),
    );
    let (sessions, capped) = cap_tmux_sessions(sessions);
    let sessions = if let Some(agents) = tabs.filter(|_| !sessions.is_empty()) {
        attach_tmux_tabs(&binary, sessions, agents).await
    } else {
        sessions
    };
    (
        TmuxProviderSnapshot {
            state: PROVIDER_STATE_AVAILABLE.into(),
            version: Some(version),
            sessions: Some(sessions),
        },
        omitted.saturating_add(capped),
    )
}

/// Spec 021 §4.1: one `list-windows -a` for every session's tabs. Any failure leaves the
/// session list exactly as a no-tabs snapshot would have it — tabs are garnish, and garnish
/// failing must never cost the meal.
async fn attach_tmux_tabs(
    binary: &Path,
    mut sessions: Vec<TmuxSessionEntry>,
    agents: &AgentTabIndex,
) -> Vec<TmuxSessionEntry> {
    let listing = run_bounded(
        binary,
        &["list-windows", "-a", "-F", TMUX_WINDOW_LIST_FORMAT],
    )
    .await;
    let Ok(output) = listing else {
        return sessions;
    };
    if !output.status_success || output.stdout_truncated {
        return sessions;
    }
    let mut windows = parse_tmux_window_list(&output.stdout, &sessions);
    for session in &mut sessions {
        session.tabs = normalize_tabs(windows.remove(&session.name).unwrap_or_default())
            .map(|tabs| annotate_agents(ProviderKind::Tmux, &session.name, tabs, agents));
    }
    sessions
}

/// Names the Agent Session in each tab the index knows about. Purely additive: a tab the index
/// says nothing about keeps exactly the shape a host without this join would have sent.
fn annotate_agents(
    kind: ProviderKind,
    session: &str,
    mut tabs: Vec<SessionTabEntry>,
    agents: &AgentTabIndex,
) -> Vec<SessionTabEntry> {
    if agents.is_empty() {
        return tabs;
    }
    for tab in &mut tabs {
        tab.agent_session_id = agents
            .get(&(kind, session.to_owned(), tab.id.clone()))
            .cloned();
    }
    tabs
}

/// Parses `list-windows -a` under `TMUX_WINDOW_LIST_FORMAT`. A line is dropped alone when any
/// fixed field breaks its rule or names a session the snapshot does not carry; free-text
/// window names take whatever remains of the line.
pub(crate) fn parse_tmux_window_list(
    stdout: &[u8],
    sessions: &[TmuxSessionEntry],
) -> std::collections::HashMap<String, Vec<SessionTabEntry>> {
    let known: std::collections::HashSet<&str> = sessions
        .iter()
        .map(|session| session.name.as_str())
        .collect();
    let mut windows: std::collections::HashMap<String, Vec<(u32, SessionTabEntry)>> =
        std::collections::HashMap::new();
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.splitn(5, ' ');
        let (Some(id), Some(active), Some(index), Some(session)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let name = fields.next().unwrap_or("");
        if !tmux_window_id(id) || !known.contains(session) {
            continue;
        }
        let Ok(index) = index.parse::<u32>() else {
            continue;
        };
        let focused = match active {
            "1" => true,
            "0" => false,
            _ => continue,
        };
        let label = sanitize_tab_label(name).unwrap_or_else(|| index.to_string());
        windows.entry(session.to_owned()).or_default().push((
            index,
            SessionTabEntry {
                id: id.to_owned(),
                label,
                focused,
                status: None,
                agent_session_id: None,
                workspace: None,
            },
        ));
    }
    windows
        .into_iter()
        .map(|(session, mut tabs)| {
            tabs.sort_by_key(|(index, _)| *index);
            (session, tabs.into_iter().map(|(_, tab)| tab).collect())
        })
        .collect()
}

/// The exact shape of a tmux window id: `@` then digits. Enforced both when parsing listings
/// and again on the pre-focus argv path, the way `target_command` re-validates session names.
pub(crate) fn tmux_window_id(id: &str) -> bool {
    id.len() > 1
        && id.len() <= 11
        && id.starts_with('@')
        && id[1..].bytes().all(|byte| byte.is_ascii_digit())
}

/// Spec 021 §4.3: display text ends here. Control characters are stripped, the result is
/// bounded on a char boundary, and an empty survivor is `None` so callers pick a fallback.
fn sanitize_tab_label(raw: &str) -> Option<String> {
    let mut label = String::new();
    for character in raw.chars().filter(|character| !character.is_control()) {
        if label.len() + character.len_utf8() > MAX_TAB_LABEL_BYTES {
            break;
        }
        label.push(character);
    }
    let trimmed = label.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Spec 021 §3.3 wire invariants, enforced in the builder so provider drift cannot invalidate
/// a snapshot: at most `MAX_TABS_PER_SESSION` tabs, at most one focused, empty becomes `None`.
fn normalize_tabs(mut tabs: Vec<SessionTabEntry>) -> Option<Vec<SessionTabEntry>> {
    tabs.truncate(MAX_TABS_PER_SESSION);
    let mut seen_focused = false;
    for tab in &mut tabs {
        if tab.focused {
            if seen_focused {
                tab.focused = false;
            }
            seen_focused = true;
        }
    }
    (!tabs.is_empty()).then_some(tabs)
}

async fn snapshot_herdr(
    config: &WorkspaceConfig,
    tabs: Option<&AgentTabIndex>,
) -> (HerdrProviderSnapshot, u32) {
    let Some(binary) = config.resolve(ProviderKind::Herdr) else {
        return (
            HerdrProviderSnapshot {
                state: PROVIDER_STATE_NOT_INSTALLED.into(),
                version: None,
                sessions: None,
            },
            0,
        );
    };
    let version = match probe_version(&binary, &["--version"], ProviderKind::Herdr).await {
        Ok(version) => version,
        Err(()) => {
            crate::drift::note("herdr", "version_probe", "invalid", "", None);
            return (error_herdr(None), 0);
        }
    };
    if !version_meets_minimum(ProviderKind::Herdr, &version) {
        return (
            HerdrProviderSnapshot {
                state: PROVIDER_STATE_UNSUPPORTED_VERSION.into(),
                version: Some(version),
                sessions: None,
            },
            0,
        );
    }

    let listing = run_bounded(&binary, &["session", "list", "--json"]).await;
    let parsed = match &listing {
        Ok(output) if output.status_success && !output.stdout_truncated => {
            parse_herdr_list(&output.stdout)
        }
        failure => {
            tracing::warn!(
                version = %version,
                detail = %provider_failure_detail(failure),
                "herdr session list failed; reporting provider error"
            );
            return (error_herdr(Some(version)), 0);
        }
    };
    let Ok((sessions, omitted)) = parsed else {
        tracing::warn!(
            version = %version,
            detail = %provider_failure_detail(&listing),
            "herdr session list was undecodable; reporting provider error"
        );
        crate::drift::note("herdr", "mux_list", "invalid", "", Some(&version));
        return (error_herdr(Some(version)), 0);
    };
    // Same split as tmux: refused entries feed the running drift total, the cap does not.
    crate::drift::note_by(
        "herdr",
        "mux_list",
        "omitted",
        "",
        Some(&version),
        u64::from(omitted),
    );
    let (sessions, capped) = cap_herdr_sessions(sessions);
    let sessions = if let Some(agents) = tabs {
        attach_herdr_tabs(&binary, sessions, agents).await
    } else {
        sessions
    };
    (
        HerdrProviderSnapshot {
            state: PROVIDER_STATE_AVAILABLE.into(),
            version: Some(version),
            sessions: Some(sessions),
        },
        omitted.saturating_add(capped),
    )
}

/// Spec 021 §4.2, extended 2026-08-25: one concurrent `--session <name> tab list` **and**
/// `--session <name> workspace list` per running session, first `MAX_HERDR_TAB_QUERIES` only.
/// Every failure shape — a herdr predating either API (the 0.7 floor), the `server_not_running`
/// error envelope, undecodable output, a timeout — yields a session without tabs (or tabs
/// without workspaces), never a degraded session list. Deliberately no drift-ledger note: a
/// floor-blessed 0.7 would page on every snapshot, and the workspace listing is the same bet.
///
/// Two calls rather than one because `tab list` alone cannot answer this: it carries a
/// `workspace_id`, which is routing data, and never the workspace's label, which is the only
/// part a person reads.
async fn attach_herdr_tabs(
    binary: &Path,
    mut sessions: Vec<HerdrSessionEntry>,
    agents: &AgentTabIndex,
) -> Vec<HerdrSessionEntry> {
    let queried: Vec<usize> = sessions
        .iter()
        .enumerate()
        .filter(|(_, session)| session.running)
        .map(|(index, _)| index)
        .take(MAX_HERDR_TAB_QUERIES)
        .collect();
    let mut handles = Vec::with_capacity(queried.len());
    for &index in &queried {
        let binary = binary.to_owned();
        let name = sessions[index].name.clone();
        handles.push(tokio::spawn(async move {
            let tab_argv = ["--session", name.as_str(), "tab", "list"];
            let workspace_argv = ["--session", name.as_str(), "workspace", "list"];
            let (tabs, workspaces) = tokio::join!(
                run_bounded(&binary, &tab_argv),
                run_bounded(&binary, &workspace_argv),
            );
            let tabs = match tabs {
                Ok(output) if output.status_success && !output.stdout_truncated => {
                    parse_herdr_tab_list(&output.stdout)
                }
                _ => None,
            };
            let workspaces = match workspaces {
                Ok(output) if output.status_success && !output.stdout_truncated => {
                    parse_herdr_workspace_labels(&output.stdout)
                }
                _ => None,
            };
            tabs.map(|tabs| resolve_workspaces(tabs, workspaces.unwrap_or_default()))
        }));
    }
    for (&index, handle) in queried.iter().zip(handles) {
        if let Ok(tabs) = handle.await {
            sessions[index].tabs = tabs.and_then(normalize_tabs).map(|tabs| {
                annotate_agents(ProviderKind::Herdr, &sessions[index].name, tabs, agents)
            });
        }
    }
    sessions
}

/// Swaps each tab's workspace **id** for its **label**, and drops the level entirely when it
/// says nothing: an unnamed id, or a session whose tabs all live in one workspace. A group
/// header drawn once over the whole list is a header the eye learns to skip.
fn resolve_workspaces(
    mut tabs: Vec<SessionTabEntry>,
    labels: std::collections::HashMap<String, String>,
) -> Vec<SessionTabEntry> {
    let distinct = tabs
        .iter()
        .filter_map(|tab| tab.workspace.as_deref())
        .filter(|id| labels.contains_key(*id))
        .collect::<std::collections::HashSet<_>>()
        .len();
    for tab in &mut tabs {
        tab.workspace = (distinct > 1)
            .then(|| {
                tab.workspace
                    .as_deref()
                    .and_then(|id| labels.get(id).cloned())
            })
            .flatten();
    }
    tabs
}

/// Lenient-but-bounded decoding of `herdr workspace list`, same posture as the tab listing: the
/// document is size- and depth-capped, unknown fields are ignored, a violating workspace is
/// dropped alone, and the error envelope is simply no workspaces.
pub(crate) fn parse_herdr_workspace_labels(
    stdout: &[u8],
) -> Option<std::collections::HashMap<String, String>> {
    if stdout.len() > HERDR_JSON_MAX_BYTES {
        return None;
    }
    let value: Value = serde_json::from_slice(stdout).ok()?;
    if container_depth(&value) > HERDR_JSON_MAX_DEPTH {
        return None;
    }
    let workspaces = value
        .as_object()?
        .get("result")?
        .as_object()?
        .get("workspaces")?
        .as_array()?;
    let mut labels = std::collections::HashMap::new();
    // Bounded by the tab cap, which is the exact right bound: every workspace holds at least
    // one tab, so a session can never need more labels than it is allowed tabs.
    for workspace in workspaces.iter().take(MAX_TABS_PER_SESSION) {
        let Some(workspace) = workspace.as_object() else {
            continue;
        };
        let Some(id) = workspace.get("workspace_id").and_then(Value::as_str) else {
            continue;
        };
        // The same alphabet the tab id rides on, because this id is that id's prefix.
        if !valid_tab_id(id) {
            continue;
        }
        let Some(label) = workspace
            .get("label")
            .and_then(Value::as_str)
            .and_then(sanitize_tab_label)
        else {
            continue;
        };
        labels.insert(id.to_owned(), label);
    }
    Some(labels)
}

/// Lenient-but-bounded decoding of `herdr tab list`, same posture as `parse_herdr_list`: the
/// document is size- and depth-capped, unknown fields are ignored, a violating tab is dropped
/// alone, and the error envelope (`server_not_running` and friends) is simply no tabs.
pub(crate) fn parse_herdr_tab_list(stdout: &[u8]) -> Option<Vec<SessionTabEntry>> {
    if stdout.len() > HERDR_JSON_MAX_BYTES {
        return None;
    }
    let value: Value = serde_json::from_slice(stdout).ok()?;
    if container_depth(&value) > HERDR_JSON_MAX_DEPTH {
        return None;
    }
    let tabs = value
        .as_object()?
        .get("result")?
        .as_object()?
        .get("tabs")?
        .as_array()?;
    let mut parsed = Vec::new();
    for tab in tabs {
        let Some(tab) = tab.as_object() else {
            continue;
        };
        let Some(id) = tab.get("tab_id").and_then(Value::as_str) else {
            continue;
        };
        if !valid_tab_id(id) {
            continue;
        }
        let label = tab
            .get("label")
            .and_then(Value::as_str)
            .and_then(sanitize_tab_label)
            .unwrap_or_else(|| id.to_owned());
        let status = tab
            .get("agent_status")
            .and_then(Value::as_str)
            .filter(|status| valid_tab_status(status))
            .map(str::to_owned);
        parsed.push(SessionTabEntry {
            id: id.to_owned(),
            label,
            focused: tab.get("focused").and_then(Value::as_bool).unwrap_or(false),
            status,
            agent_session_id: None,
            // The **id** at this point, not the label. `attach_herdr_tabs` is the only caller
            // and swaps it for the workspace's label, dropping any id the workspace listing did
            // not name — so an unresolved id can never reach the wire.
            workspace: tab
                .get("workspace_id")
                .and_then(Value::as_str)
                .filter(|id| valid_tab_id(id))
                .map(str::to_owned),
        });
    }
    Some(parsed)
}

/// Spec 021 §5: the best-effort pre-focus before an attach spawn. Bounded like every non-PTY
/// provider call; a stale or foreign tab fails here and the attach proceeds to the session's
/// current tab. The tmux target uses the scoped `=session:@id` form because it validates
/// membership for free — probed 2026-08-18: a window id outside the named session is
/// `can't find window`, exit 1, no side effect.
pub(crate) async fn focus_tab(
    config: &WorkspaceConfig,
    kind: ProviderKind,
    session: &str,
    tab: &str,
) -> bool {
    if !valid_session_name(session) || !valid_tab_id(tab) {
        return false;
    }
    let Some(binary) = config.resolve(kind) else {
        return false;
    };
    match kind {
        ProviderKind::Tmux => {
            if !tmux_window_id(tab) {
                return false;
            }
            let target = format!("={session}:{tab}");
            run_bounded(&binary, &["select-window", "-t", &target])
                .await
                .is_ok_and(|output| output.status_success)
        }
        ProviderKind::Herdr => {
            run_bounded(&binary, &["--session", session, "tab", "focus", tab])
                .await
                .is_ok_and(|output| {
                    // herdr reports API failures as an error envelope on a zero exit, so the
                    // envelope is the only truth worth logging.
                    output.status_success
                        && !String::from_utf8_lossy(&output.stdout).contains("\"error\"")
                })
        }
    }
}

/// What a multiplexer knows about the pane a phone is looking at: where it is standing, and
/// which agent — if any — is running in it.
///
/// One owner for both because one provider call answers both. herdr's `pane current` carries
/// `foreground_cwd` and `agent` in the same envelope, so asking twice would be two spawns for
/// one question, and the two answers could disagree across the gap between them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PaneFacts {
    /// Absolute and validated, or absent. Never a relative or provider-shaped answer.
    pub(crate) cwd: Option<String>,
    /// The provider's own word for what is running: `claude`, `codex`, `pi`. Carried verbatim
    /// and never widened here — a caller that cares matches the exact name it supports, so a
    /// dialect this build has never met reads as "no agent" rather than as the nearest one.
    ///
    /// Absent on tmux, which is a gap rather than an answer — see `pane_facts`.
    pub(crate) agent: Option<String>,
}

/// Where a multiplexer session is standing, for Spec 015 §11.1.
///
/// The shell is the wrong thing to ask: OSC 7 never arrives in Ciao's terminal, so every
/// relative token used to refuse. The multiplexer already knows, and its answer is the safer
/// one besides — a pane's directory is always local, where an OSC 7 report from a remote shell
/// under ssh would name a directory that only exists on the other machine.
///
/// herdr's `foreground_cwd` in preference to the pane's own: a path on screen was printed by
/// the program that is running, and an agent started from somewhere other than its shell's
/// directory is the case that motivated this.
///
/// Best effort throughout. An absent provider, a wedged one, a session that has since closed,
/// or an answer that is not an absolute path all return `None`, and the preview then refuses a
/// relative token exactly as it does today.
pub(crate) async fn session_cwd(
    config: &WorkspaceConfig,
    kind: ProviderKind,
    session: &str,
) -> Option<String> {
    pane_facts(config, kind, session).await.cwd
}

/// The full read behind `session_cwd`, plus which agent the provider says is in the pane.
///
/// **tmux reports no agent, deliberately.** Its `#{pane_current_command}` is the foreground
/// process's *name*, and Claude Code renames itself to its own version string — a pane running
/// it reports `2.1.237`, not `claude` (measured on tmux 3.7b, 2026-08-20). Matching that would
/// be gating a feature on a semver-shaped string, which any process could wear. Identifying the
/// pane's foreground process properly needs the tty/process-group walk that `agent_route` does
/// from a known pid, and there is no pid here without another provider round trip.
///
/// ponytail: herdr answers for free and is the provider the app is used against; tmux degrades
/// to no agent, which callers already treat as "offer nothing". Give tmux a real answer by
/// asking for `#{pane_tty}` and resolving its foreground group, not by trusting the name.
pub(crate) async fn pane_facts(
    config: &WorkspaceConfig,
    kind: ProviderKind,
    session: &str,
) -> PaneFacts {
    inner_pane_facts(config, kind, session)
        .await
        .unwrap_or_default()
}

async fn inner_pane_facts(
    config: &WorkspaceConfig,
    kind: ProviderKind,
    session: &str,
) -> Option<PaneFacts> {
    if !valid_session_name(session) {
        return None;
    }
    let binary = config.resolve(kind)?;
    let mut agent = None;
    let reported = match kind {
        ProviderKind::Tmux => {
            // The scoped `=session` form for the same reason `focus_tab` uses it: exact-name
            // matching rather than tmux's prefix search, which could answer for a different
            // session whose name merely starts the same way.
            //
            // The trailing colon is load-bearing and was missing until 2026-08-20. `-t` here
            // wants a target-pane, and `=name` alone names a session, so tmux resolved it to no
            // pane and printed an empty line on a *zero* exit — which `absolute_directory` then
            // dropped. The symptom was silent: every relative preview token refused on tmux
            // while herdr worked, so it read as "preview is broken for me" rather than as a
            // provider bug. `=name:` is the session's current pane, and it still refuses the
            // prefix search (verified on tmux 3.7b: with `api` and `apiary` both live, `=api:`
            // answers for `api`, and once `api` is killed it answers for nothing rather than
            // falling through to `apiary`).
            //
            // A shell stub cannot reproduce tmux's target resolution, so the test below fences
            // the argv rather than the behavior. The argv is the part that was wrong.
            let target = format!("={session}:");
            let output = run_bounded(
                &binary,
                &["display", "-p", "-t", &target, "#{pane_current_path}"],
            )
            .await
            .ok()?;
            if !output.status_success || output.stdout_truncated {
                return None;
            }
            String::from_utf8(output.stdout).ok()?
        }
        ProviderKind::Herdr => {
            let output = run_bounded(&binary, &["--session", session, "pane", "current"])
                .await
                .ok()?;
            if !output.status_success || output.stdout_truncated {
                return None;
            }
            // Same read as `focus_tab`: herdr reports API failures as an error envelope on a
            // zero exit, so a missing `result.pane` is the failure and there is nothing else
            // to inspect.
            let value: Value = serde_json::from_slice(&output.stdout).ok()?;
            let pane = value.get("result")?.get("pane")?;
            // Read before the `?` on the directory below: a pane whose agent is known but whose
            // directory is not is still worth reporting the agent for, and the two fields fail
            // independently.
            agent = pane
                .get("agent")
                .and_then(Value::as_str)
                .filter(|name| valid_agent_name(name))
                .map(str::to_owned);
            let Some(directory) = pane
                .get("foreground_cwd")
                .or_else(|| pane.get("cwd"))
                .and_then(Value::as_str)
            else {
                return Some(PaneFacts { cwd: None, agent });
            };
            directory.to_owned()
        }
    };
    Some(PaneFacts {
        cwd: absolute_directory(reported.trim()),
        agent,
    })
}

/// A provider's name for what it found is input like any other. Bounded lowercase ASCII only,
/// because this becomes a match arm and travels to a phone; a vendor that starts reporting
/// something longer or stranger is discarded rather than carried.
fn valid_agent_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// A provider's answer is input like any other. Only an absolute, bounded, NUL-free path may
/// become the base a relative token resolves against; anything else is discarded rather than
/// joined, because a nonsense base turns "no such file" into a silently different question.
fn absolute_directory(reported: &str) -> Option<String> {
    if !reported.starts_with('/')
        || reported.len() > crate::downloads::MAX_PATH_BYTES
        || reported.contains('\0')
    {
        return None;
    }
    Some(reported.to_owned())
}

async fn probe_version(binary: &Path, args: &[&str], kind: ProviderKind) -> Result<String, ()> {
    let result = run_bounded(binary, args).await;
    let parsed = match &result {
        Ok(output) if output.status_success && !output.stdout_truncated => {
            parse_version_stdout(kind, &output.stdout)
        }
        _ => None,
    };
    if parsed.is_none() {
        tracing::warn!(
            provider = ?kind,
            detail = %provider_failure_detail(&result),
            "provider version probe failed; reporting provider error"
        );
    }
    parsed.ok_or(())
}

/// One bounded log line naming why a provider probe failed. The snapshot carries a categorical
/// state only, so the phone can say no more than "unavailable"; without this line the reason
/// exists nowhere at all, and a host that reports an unusable tmux is undiagnosable remotely.
fn provider_failure_detail(result: &Result<BoundedOutput, ProviderExecError>) -> String {
    match result {
        Err(error) => format!("{error:?}"),
        Ok(output) => format!(
            "success={} stdout={:?} stderr={:?}",
            output.status_success,
            clip_provider_output(&output.stdout),
            clip_provider_output(&output.stderr),
        ),
    }
}

fn clip_provider_output(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim()
        .chars()
        .take(200)
        .collect()
}

pub(crate) struct BoundedOutput {
    pub status_success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderExecError {
    SpawnFailed,
    TimedOut,
    WaitFailed,
}

/// Runs one fixed provider argv with no stdin, the cleaned PTY environment policy, a 3-second
/// SIGKILL timeout, and capped stdout/stderr reads. Bytes beyond a cap are drained and discarded
/// so a chatty child is truncated without ever blocking on a full pipe.
pub(crate) async fn run_bounded(
    program: &Path,
    args: &[&str],
) -> Result<BoundedOutput, ProviderExecError> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    apply_clean_process_environment(&mut command).map_err(|_| ProviderExecError::SpawnFailed)?;
    let mut child = command
        .spawn()
        .map_err(|_| ProviderExecError::SpawnFailed)?;
    let stdout = child.stdout.take().ok_or(ProviderExecError::SpawnFailed)?;
    let stderr = child.stderr.take().ok_or(ProviderExecError::SpawnFailed)?;

    let bounded = timeout(PROVIDER_EXEC_TIMEOUT, async {
        let (stdout, stderr) = tokio::join!(
            read_capped(stdout, PROVIDER_STDOUT_CAP),
            read_capped(stderr, PROVIDER_STDERR_CAP),
        );
        let status = child.wait().await;
        (stdout, stderr, status)
    })
    .await;

    match bounded {
        Ok(((stdout, stdout_truncated), (stderr, stderr_truncated), Ok(status))) => {
            Ok(BoundedOutput {
                status_success: status.success(),
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
            })
        }
        Ok((_, _, Err(_))) => Err(ProviderExecError::WaitFailed),
        Err(_) => {
            // `child` was moved into the timed-out future, which is dropped here;
            // `kill_on_drop(true)` sends SIGKILL and the runtime reaps the child.
            Err(ProviderExecError::TimedOut)
        }
    }
}

/// Detaches exactly the tmux client connected to Ciao's trusted PTY. The target is derived from
/// the local PTY allocation, never from a remote request, and provider output remains bounded and
/// discarded like every other non-PTY provider invocation.
pub(crate) async fn detach_tmux_client(program: &Path, client_tty: &Path) -> bool {
    let Some(target) = valid_tmux_client_tty(client_tty) else {
        return false;
    };
    run_bounded(program, &["detach-client", "-t", target])
        .await
        .is_ok_and(|output| output.status_success)
}

fn valid_tmux_client_tty(client_tty: &Path) -> Option<&str> {
    let target = client_tty.file_name()?.to_str()?;
    let allocated_locally = match client_tty.parent()?.to_str()? {
        // macOS and the BSDs name the client side /dev/ttysNNN.
        "/dev" => target.starts_with("tty"),
        // Linux puts it under /dev/pts and names it only by index, so requiring a "tty" prefix
        // rejected every terminal Ciao allocates there and detach-client always failed.
        "/dev/pts" => !target.is_empty() && target.bytes().all(|byte| byte.is_ascii_digit()),
        _ => return None,
    };
    (allocated_locally
        && target.len() <= 64
        && target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    .then_some(client_tty.to_str()?)
}

pub(crate) async fn read_capped<R>(mut reader: R, cap: usize) -> (Vec<u8>, bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut truncated = false;
    let mut chunk = [0_u8; 4096];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                let remaining = cap.saturating_sub(buffer.len());
                let take = count.min(remaining);
                buffer.extend_from_slice(&chunk[..take]);
                truncated |= take < count;
            }
        }
    }
    (buffer, truncated)
}

pub(crate) fn parse_version_stdout(kind: ProviderKind, stdout: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(stdout).ok()?;
    let first = text.lines().next()?;
    let prefix = match kind {
        ProviderKind::Tmux => "tmux ",
        ProviderKind::Herdr => "herdr ",
    };
    let token = first.strip_prefix(prefix)?.trim();
    let valid = !token.is_empty()
        && token.len() <= MAX_PROVIDER_VERSION_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    valid.then(|| token.to_owned())
}

pub(crate) fn version_meets_minimum(kind: ProviderKind, version: &str) -> bool {
    let parsed = match kind {
        // tmux versions use a numeric major/minor plus an optional alphabetic suffix (`3.6b`).
        ProviderKind::Tmux => parse_tmux_version(version),
        // Herdr uses a numeric dotted release core and may append a bounded prerelease suffix.
        ProviderKind::Herdr => parse_herdr_version(version),
    };
    let Some((major, minor)) = parsed else {
        return false;
    };
    match kind {
        ProviderKind::Tmux => major >= TMUX_MIN_MAJOR,
        ProviderKind::Herdr => (major, minor) >= HERDR_MIN_MAJOR_MINOR,
    }
}

fn parse_tmux_version(version: &str) -> Option<(u64, u64)> {
    // tmux's master branch reports `next-<upcoming release>` between releases, so `next-3.4` is
    // a build *after* 3.3, not an unparseable string. Refusing it told an owner running a
    // current development build that their tmux was too old to support — the failure a floor is
    // least able to explain, because the number it printed was higher than the one it demanded.
    //
    // Reading it as the upcoming release slightly over-claims (it is pre-3.4, not 3.4), which
    // cannot matter while the only question asked is whether it clears 3.0. A bare `next` still
    // has no numbers in it and is still refused.
    let version = version.strip_prefix("next-").unwrap_or(version);
    let (major, minor_and_suffix) = version.split_once('.')?;
    if major.is_empty() || !major.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let digits = minor_and_suffix
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count();
    if digits == 0
        || !minor_and_suffix[digits..]
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic())
    {
        return None;
    }
    Some((
        major.parse().ok()?,
        minor_and_suffix[..digits].parse().ok()?,
    ))
}

fn parse_herdr_version(version: &str) -> Option<(u64, u64)> {
    let (release, prerelease) = match version.split_once('-') {
        Some((release, suffix)) => (release, Some(suffix)),
        None => (version, None),
    };
    // The release core has at least major/minor. Parsing every component as u64 makes integer
    // overflow categorical rather than silently truncating it.
    let parts: Vec<&str> = release.split('.').collect();
    if parts.len() < 2
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    for part in &parts {
        let _: u64 = part.parse().ok()?;
    }
    if let Some(suffix) = prerelease {
        let bytes = suffix.as_bytes();
        if bytes.is_empty()
            || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return None;
        }
    }
    Some((parts[0].parse().ok()?, parts[1].parse().ok()?))
}

/// Parses `tmux list-sessions` output joined on 0x1F.
///
/// The daemon runs providers with a cleared environment, so tmux never sees a UTF-8 locale and
/// rewrites the control character in the format string rather than emitting it. Which rewrite
/// depends on the version: 3.6 substitutes `_`, while 3.4 writes the octal escape `\037` as four
/// literal characters. Both are parsed here because reading only the raw byte meant every session
/// on an Ubuntu host was silently omitted and the workspace looked empty.
///
/// The escaped form is split from the left and the substituted form from the right, since a
/// session name may contain `_` but never a backslash. Lines that do not have exactly four
/// fields, contain a nonconforming session name, or carry non-numeric metadata are omitted and
/// counted, never partially trusted.
pub(crate) fn parse_tmux_list(stdout: &[u8]) -> (Vec<TmuxSessionEntry>, u32) {
    let mut sessions = Vec::new();
    let mut omitted = 0_u32;
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let parsed = (|| {
            let [name, attached, windows, created] = if line.contains(UNIT_SEPARATOR) {
                let fields: Vec<&str> = line.split(UNIT_SEPARATOR).collect();
                <[&str; 4]>::try_from(fields).ok()?
            } else if line.contains(UNIT_SEPARATOR_ESCAPE) {
                let fields: Vec<&str> = line.split(UNIT_SEPARATOR_ESCAPE).collect();
                <[&str; 4]>::try_from(fields).ok()?
            } else {
                let fields: Vec<&str> = line.rsplitn(4, '_').collect();
                let [created, windows, attached, name] = <[&str; 4]>::try_from(fields).ok()?;
                [name, attached, windows, created]
            };
            if !valid_session_name(name) {
                return None;
            }
            Some(TmuxSessionEntry {
                name: name.to_owned(),
                attached: attached.parse::<u64>().ok()? > 0,
                windows: windows.parse().ok()?,
                created_unix: created.parse().ok()?,
                tabs: None,
            })
        })();
        match parsed {
            Some(session) => sessions.push(session),
            None => omitted = omitted.saturating_add(1),
        }
    }
    (sessions, omitted)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HerdrParseError;

/// Lenient-but-bounded decoding of `herdr session list --json`: unknown fields are ignored,
/// container depth is limited, the document is size-capped, and only `name`, `running`, and
/// `default` are consumed. Filesystem paths in the document are never retained.
pub(crate) fn parse_herdr_list(
    stdout: &[u8],
) -> Result<(Vec<HerdrSessionEntry>, u32), HerdrParseError> {
    if stdout.len() > HERDR_JSON_MAX_BYTES {
        return Err(HerdrParseError);
    }
    let value: Value = serde_json::from_slice(stdout).map_err(|_| HerdrParseError)?;
    if container_depth(&value) > HERDR_JSON_MAX_DEPTH {
        return Err(HerdrParseError);
    }
    let entries = value
        .as_object()
        .and_then(|object| object.get("sessions"))
        .and_then(Value::as_array)
        .ok_or(HerdrParseError)?;
    let mut sessions = Vec::new();
    let mut omitted = 0_u32;
    for entry in entries {
        let parsed = entry.as_object().and_then(|object| {
            let name = object.get("name")?.as_str()?;
            if !valid_session_name(name) {
                return None;
            }
            Some(HerdrSessionEntry {
                name: name.to_owned(),
                running: object
                    .get("running")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                is_default: object
                    .get("default")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                tabs: None,
            })
        });
        match parsed {
            Some(session) => sessions.push(session),
            None => omitted = omitted.saturating_add(1),
        }
    }
    Ok((sessions, omitted))
}

fn container_depth(value: &Value) -> usize {
    match value {
        Value::Object(map) => 1 + map.values().map(container_depth).max().unwrap_or(0),
        Value::Array(items) => 1 + items.iter().map(container_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Caps tmux sessions at the per-provider bound, keeping the most recently created sessions
/// (ties broken by listing order) while preserving the original relative order.
fn cap_tmux_sessions(sessions: Vec<TmuxSessionEntry>) -> (Vec<TmuxSessionEntry>, u32) {
    if sessions.len() <= MAX_SESSIONS_PER_PROVIDER {
        return (sessions, 0);
    }
    let overflow = (sessions.len() - MAX_SESSIONS_PER_PROVIDER) as u32;
    let mut ranked: Vec<usize> = (0..sessions.len()).collect();
    ranked.sort_by_key(|&index| (std::cmp::Reverse(sessions[index].created_unix), index));
    let mut keep = vec![false; sessions.len()];
    for &index in ranked.iter().take(MAX_SESSIONS_PER_PROVIDER) {
        keep[index] = true;
    }
    let kept = sessions
        .into_iter()
        .zip(keep)
        .filter_map(|(session, keep)| keep.then_some(session))
        .collect();
    (kept, overflow)
}

/// Caps Herdr sessions at the per-provider bound, keeping listing order (default session first).
fn cap_herdr_sessions(mut sessions: Vec<HerdrSessionEntry>) -> (Vec<HerdrSessionEntry>, u32) {
    if sessions.len() <= MAX_SESSIONS_PER_PROVIDER {
        return (sessions, 0);
    }
    let overflow = (sessions.len() - MAX_SESSIONS_PER_PROVIDER) as u32;
    sessions.truncate(MAX_SESSIONS_PER_PROVIDER);
    (sessions, overflow)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, time::Instant as StdInstant};

    use nix::{errno::Errno, sys::signal::kill, unistd::Pid};
    use tempfile::tempdir;

    use super::*;

    /// The maintenance sandbox supplies bytes from a real provider in a disposable HOME.
    /// Exercise the production parser rather than implement another parser in its JS probe.
    #[test]
    #[ignore = "requires an explicitly supplied real vendor-maintenance sample"]
    fn vendor_maintenance_provider_probe() {
        let sample = std::env::var("CIAO_VENDOR_PROVIDER_SAMPLE").expect("real sample required");
        assert!(sample.len() <= 16 * 1024);
        let provider = std::env::var("CIAO_VENDOR_PROVIDER").expect("provider required");
        assert!(matches!(provider.as_str(), "tmux" | "herdr"));
        println!("ciao-provider-probe-ran {provider}");
        if provider == "tmux" {
            let (rows, omitted) = parse_tmux_list(sample.as_bytes());
            assert_eq!(omitted, 0);
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].name, "ciao-probe");
            assert!(!rows[0].attached);
            assert_eq!(rows[0].windows, 1);
            assert!(rows[0].created_unix > 0);
        } else {
            let (rows, omitted) = parse_herdr_list(sample.as_bytes()).expect("provider JSON");
            assert_eq!(omitted, 0);
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].name, "default");
            assert!(rows[0].is_default);
            assert!(!rows[0].running);
        }
    }

    fn fixture() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase2/provider-output-v1.json"
        );
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn targets_fixture() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase2/terminal-targets-v1.json"
        );
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn write_stub(directory: &Path, name: &str, script: &str) -> PathBuf {
        let path = directory.join(name);
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn provider_resolution_uses_only_fixed_directories_in_order() {
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        let elsewhere = tempdir().unwrap();
        write_stub(second.path(), "tmux", "exit 0");
        write_stub(elsewhere.path(), "herdr", "exit 0");

        let config = WorkspaceConfig::with_binary_dirs(vec![
            first.path().to_owned(),
            second.path().to_owned(),
        ]);
        assert_eq!(
            config.resolve(ProviderKind::Tmux).unwrap(),
            second.path().join("tmux")
        );
        // A binary outside the fixed directory list is never found. There is no PATH search:
        // resolution joins the fixed directories with the provider name and nothing else.
        assert_eq!(config.resolve(ProviderKind::Herdr), None);

        // Preference order: the earlier fixed directory wins.
        write_stub(first.path(), "tmux", "exit 0");
        assert_eq!(
            config.resolve(ProviderKind::Tmux).unwrap(),
            first.path().join("tmux")
        );

        // A non-executable candidate is skipped.
        let plain = first.path().join("herdr");
        fs::write(&plain, "not executable").unwrap();
        assert_eq!(config.resolve(ProviderKind::Herdr), None);

        let home = Path::new("/home/alpha");
        let production = WorkspaceConfig::for_home(home);
        let mut expected: Vec<PathBuf> = PROVIDER_BINARY_DIRS.iter().map(PathBuf::from).collect();
        expected.extend(
            PROVIDER_HOME_RELATIVE_DIRS
                .iter()
                .map(|relative| home.join(relative)),
        );
        assert_eq!(production.binary_dirs, expected);
        // Every candidate directory is absolute; there is no PATH or relative lookup.
        assert!(production.binary_dirs.iter().all(|dir| dir.is_absolute()));
    }

    #[test]
    fn version_parsing_matches_shared_fixture_and_rejects_garbage() {
        let fixture = fixture();
        let tmux = fixture.get("tmux").unwrap();
        let herdr = fixture.get("herdr").unwrap();
        assert_eq!(
            parse_version_stdout(
                ProviderKind::Tmux,
                tmux.get("version_stdout")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .as_bytes()
            )
            .as_deref(),
            tmux.get("version_expected").unwrap().as_str()
        );
        assert_eq!(
            parse_version_stdout(
                ProviderKind::Herdr,
                herdr
                    .get("version_stdout")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .as_bytes()
            )
            .as_deref(),
            herdr.get("version_expected").unwrap().as_str()
        );

        let below = parse_version_stdout(
            ProviderKind::Tmux,
            tmux.get("version_below_minimum_stdout")
                .unwrap()
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        assert!(!version_meets_minimum(ProviderKind::Tmux, &below));
        assert!(version_meets_minimum(ProviderKind::Tmux, "3.6b"));
        assert!(version_meets_minimum(ProviderKind::Herdr, "0.7.4"));
        assert!(!version_meets_minimum(ProviderKind::Herdr, "0.6.9"));
        assert!(version_meets_minimum(ProviderKind::Herdr, "1.0.0"));

        assert_eq!(parse_version_stdout(ProviderKind::Tmux, b"zsh 5.9"), None);
        assert_eq!(parse_version_stdout(ProviderKind::Tmux, b"tmux "), None);
        assert_eq!(
            parse_version_stdout(ProviderKind::Tmux, b"tmux ver sion"),
            None
        );
        assert_eq!(
            parse_version_stdout(ProviderKind::Tmux, &[0xff, 0xfe]),
            None
        );
        let oversize = format!("tmux {}", "9".repeat(65));
        assert_eq!(
            parse_version_stdout(ProviderKind::Tmux, oversize.as_bytes()),
            None
        );
        // A development build off tmux master. `next-3.4` is newer than 3.3, and reading it as
        // unparseable reported "unsupported version" to a host running a tmux ahead of the
        // floor rather than behind it. Bare `next` carries no release at all and stays refused.
        let phase3_tmux: Value = serde_json::from_slice(
            &fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../protocol/fixtures/phase3/provider-versions-v1.json"
            ))
            .unwrap(),
        )
        .unwrap();
        for token in phase3_tmux
            .get("tmux_qualifies")
            .unwrap()
            .as_array()
            .unwrap()
        {
            let token = token.as_str().unwrap();
            assert!(
                version_meets_minimum(ProviderKind::Tmux, token),
                "{token} should clear the tmux floor"
            );
        }
        for token in phase3_tmux
            .get("tmux_unsupported")
            .unwrap()
            .as_array()
            .unwrap()
        {
            let token = token.as_str().unwrap();
            assert!(
                !version_meets_minimum(ProviderKind::Tmux, token),
                "{token} should not clear the tmux floor"
            );
        }
        assert!(!version_meets_minimum(ProviderKind::Tmux, "next"));
        assert!(!version_meets_minimum(ProviderKind::Tmux, "3garbage"));
        assert!(!version_meets_minimum(ProviderKind::Herdr, "0.7garbage"));
        assert!(version_meets_minimum(ProviderKind::Herdr, "0.7.4-preview"));

        let phase3_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase3/provider-versions-v1.json"
        );
        let phase3: Value = serde_json::from_slice(&fs::read(phase3_path).unwrap()).unwrap();
        for token in phase3.get("valid_tokens").unwrap().as_array().unwrap() {
            let token = token.as_str().unwrap();
            assert!(token.len() <= MAX_PROVIDER_VERSION_BYTES);
            let line = format!("herdr {token}");
            assert_eq!(
                parse_version_stdout(ProviderKind::Herdr, line.as_bytes()).as_deref(),
                Some(token)
            );
        }
        for token in phase3.get("invalid_tokens").unwrap().as_array().unwrap() {
            let line = format!("herdr {}", token.as_str().unwrap());
            assert_eq!(
                parse_version_stdout(ProviderKind::Herdr, line.as_bytes()),
                None
            );
        }
        for token in phase3.get("herdr_qualifies").unwrap().as_array().unwrap() {
            assert!(version_meets_minimum(
                ProviderKind::Herdr,
                token.as_str().unwrap()
            ));
        }
        for token in phase3.get("herdr_unsupported").unwrap().as_array().unwrap() {
            assert!(!version_meets_minimum(
                ProviderKind::Herdr,
                token.as_str().unwrap()
            ));
        }
    }

    /// A provider that errors reaches the phone as the single word "unavailable", so the daemon
    /// log has to carry the sentence tmux actually printed — the failure the owner hit was a
    /// working binary whose reason lived nowhere.
    #[test]
    fn provider_failure_detail_carries_the_provider_diagnostic() {
        let detail = provider_failure_detail(&Ok(BoundedOutput {
            status_success: false,
            stdout: Vec::new(),
            stderr: b"protocol version mismatch (client 8, server 7)\n".to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        }));
        assert!(detail.contains("success=false"), "{detail}");
        assert!(detail.contains("protocol version mismatch"), "{detail}");

        assert_eq!(
            provider_failure_detail(&Err(ProviderExecError::TimedOut)),
            "TimedOut"
        );
        // A chatty provider must not push a whole screen of output into one log line.
        let noisy = provider_failure_detail(&Ok(BoundedOutput {
            status_success: false,
            stdout: vec![b'x'; 4096],
            stderr: Vec::new(),
            stdout_truncated: true,
            stderr_truncated: false,
        }));
        assert!(noisy.contains(&"x".repeat(200)), "{noisy}");
        assert!(!noisy.contains(&"x".repeat(201)), "{noisy}");
    }

    #[test]
    fn tmux_list_parsing_matches_fixture_and_omits_violators() {
        let fixture = fixture();
        let tmux = fixture.get("tmux").unwrap();
        let stdout = tmux.get("list_stdout").unwrap().as_str().unwrap();
        let expected = tmux.get("list_expected").unwrap();
        let (sessions, omitted) = parse_tmux_list(stdout.as_bytes());
        let expected_sessions: Vec<TmuxSessionEntry> =
            serde_json::from_value(expected.get("sessions").unwrap().clone()).unwrap();
        assert_eq!(sessions, expected_sessions);
        assert_eq!(
            u64::from(omitted),
            expected.get("omitted").unwrap().as_u64().unwrap()
        );

        // Separator injection inside a would-be name splits the line into five fields → omitted.
        let injected = "evil\u{1f}name\u{1f}1\u{1f}2\u{1f}3\n";
        let (sessions, omitted) = parse_tmux_list(injected.as_bytes());
        assert!(sessions.is_empty());
        assert_eq!(omitted, 1);

        // A LaunchAgent commonly has no LANG. tmux then sanitizes the three 0x1F format
        // separators to underscores; right-splitting preserves underscores in the session name.
        let (sessions, omitted) = parse_tmux_list(b"ciao_perf_0_2_1784603942\n");
        assert_eq!(omitted, 0);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].name, "ciao_perf");
        assert!(!sessions[0].attached);
        assert_eq!(sessions[0].windows, 2);
        assert_eq!(sessions[0].created_unix, 1_784_603_942);

        // Invalid UTF-8 collapses to replacement characters, which fail the name rule.
        let (sessions, omitted) = parse_tmux_list(b"\xff\xfe\x1f1\x1f1\x1f1\n");
        assert!(sessions.is_empty());
        assert_eq!(omitted, 1);

        let (sessions, omitted) = parse_tmux_list(b"");
        assert!(sessions.is_empty());
        assert_eq!(omitted, 0);
    }

    /// Bytes copied from a real `tmux 3.4` on Ubuntu, invoked the way the daemon invokes it: with
    /// a cleared environment and therefore no UTF-8 locale. Every session was being omitted, so a
    /// workspace with sessions in it reported none at all, and nothing in the suite noticed
    /// because the only parsing coverage used the raw separator the daemon never receives there.
    #[test]
    fn tmux_list_parsing_accepts_the_escape_written_without_a_utf8_locale() {
        let escaped = b"ciao-probe-1234\\0370\\0371\\0371785206554\n";
        let (sessions, omitted) = parse_tmux_list(escaped);
        assert_eq!(omitted, 0);
        assert_eq!(
            sessions,
            vec![TmuxSessionEntry {
                name: "ciao-probe-1234".to_owned(),
                attached: false,
                windows: 1,
                created_unix: 1_785_206_554,
                tabs: None,
            }]
        );

        // A name may contain an underscore, so the escaped form must not be mistaken for the
        // substituted one and split on the wrong character.
        let underscored = b"my_session\\0371\\0372\\0371785206554\n";
        let (sessions, omitted) = parse_tmux_list(underscored);
        assert_eq!(omitted, 0);
        assert_eq!(sessions[0].name, "my_session");
        assert!(sessions[0].attached);
        assert_eq!(sessions[0].windows, 2);
    }

    // Both platforms' naming is asserted here even though the check is pure path arithmetic and
    // runs anywhere. Covering only the macOS spelling is what let Linux detach stay broken: the
    // test looked like coverage while encoding one platform's assumption.
    #[test]
    fn tmux_client_detach_target_accepts_only_local_ttys() {
        assert_eq!(
            valid_tmux_client_tty(Path::new("/dev/ttys123")),
            Some("/dev/ttys123")
        );
        assert_eq!(
            valid_tmux_client_tty(Path::new("/dev/tty.test-1")),
            Some("/dev/tty.test-1")
        );
        assert_eq!(
            valid_tmux_client_tty(Path::new("/dev/pts/0")),
            Some("/dev/pts/0")
        );
        assert_eq!(
            valid_tmux_client_tty(Path::new("/dev/pts/1024")),
            Some("/dev/pts/1024")
        );
        assert_eq!(valid_tmux_client_tty(Path::new("/tmp/ttys123")), None);
        assert_eq!(valid_tmux_client_tty(Path::new("/dev/null")), None);
        assert_eq!(valid_tmux_client_tty(Path::new("/dev/tty/child")), None);
        // Only the index names a Linux terminal; anything else under /dev/pts is not ours.
        assert_eq!(valid_tmux_client_tty(Path::new("/dev/pts/ptmx")), None);
        assert_eq!(valid_tmux_client_tty(Path::new("/dev/pts")), None);
        assert_eq!(valid_tmux_client_tty(Path::new("/dev/pts/../null")), None);
    }

    #[test]
    fn herdr_list_parsing_is_lenient_bounded_and_path_free() {
        let fixture = fixture();
        let herdr = fixture.get("herdr").unwrap();
        let stdout = herdr.get("list_stdout").unwrap().as_str().unwrap();
        let expected = herdr.get("list_expected").unwrap();
        let (sessions, omitted) = parse_herdr_list(stdout.as_bytes()).unwrap();
        let expected_sessions: Vec<HerdrSessionEntry> =
            serde_json::from_value(expected.get("sessions").unwrap().clone()).unwrap();
        assert_eq!(sessions, expected_sessions);
        assert_eq!(
            u64::from(omitted),
            expected.get("omitted").unwrap().as_u64().unwrap()
        );
        // The parsed entries carry no filesystem path fields by construction.
        let encoded = serde_json::to_string(&sessions).unwrap();
        assert!(!encoded.contains("session_dir"));
        assert!(!encoded.contains("socket_path"));
        assert!(!encoded.contains('/'));

        // Depth beyond four container levels fails closed.
        let deep = br#"{"sessions":[{"name":"a","running":true,"deep":{"deeper":{"deepest":1}}}]}"#;
        assert_eq!(parse_herdr_list(deep), Err(HerdrParseError));

        // Oversized documents fail closed.
        let padding = "x".repeat(HERDR_JSON_MAX_BYTES);
        let oversize = format!(r#"{{"sessions":[],"pad":"{padding}"}}"#);
        assert_eq!(parse_herdr_list(oversize.as_bytes()), Err(HerdrParseError));

        assert_eq!(parse_herdr_list(b"not json"), Err(HerdrParseError));
        assert_eq!(parse_herdr_list(b"[]"), Err(HerdrParseError));

        // Missing name or non-object entries are omitted and counted, not fatal.
        let partial = br#"{"sessions":[{"running":true},42,{"name":"ok","running":false}]}"#;
        let (sessions, omitted) = parse_herdr_list(partial).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].name, "ok");
        assert_eq!(omitted, 2);
    }

    #[test]
    fn session_caps_keep_most_recent_tmux_and_first_herdr() {
        let tmux: Vec<TmuxSessionEntry> = (0..70)
            .map(|index| TmuxSessionEntry {
                name: format!("s{index}"),
                attached: false,
                windows: 1,
                created_unix: 1_000 + index,
                tabs: None,
            })
            .collect();
        let (kept, omitted) = cap_tmux_sessions(tmux);
        assert_eq!(kept.len(), MAX_SESSIONS_PER_PROVIDER);
        assert_eq!(omitted, 6);
        // The six oldest sessions are dropped; order is preserved for the rest.
        assert_eq!(kept.first().unwrap().name, "s6");
        assert_eq!(kept.last().unwrap().name, "s69");

        let herdr: Vec<HerdrSessionEntry> = (0..70)
            .map(|index| HerdrSessionEntry {
                name: format!("h{index}"),
                running: false,
                is_default: index == 0,
                tabs: None,
            })
            .collect();
        let (kept, omitted) = cap_herdr_sessions(herdr);
        assert_eq!(kept.len(), MAX_SESSIONS_PER_PROVIDER);
        assert_eq!(omitted, 6);
        assert_eq!(kept.first().unwrap().name, "h0");
        assert_eq!(kept.last().unwrap().name, "h63");
    }

    #[test]
    fn target_argv_is_exactly_the_fixture_argv_for_all_targets() {
        let fixture = targets_fixture();
        let argv = fixture.get("argv").unwrap();
        let binary = PathBuf::from("/opt/homebrew/bin/tmux");
        let home = PathBuf::from("/Users/example");
        for (case, target, session) in [
            ("tmux_attach", TerminalTarget::TmuxAttach, "api"),
            ("tmux_create", TerminalTarget::TmuxCreate, "new-work"),
            ("herdr_attach", TerminalTarget::HerdrAttach, "default"),
            ("herdr_create", TerminalTarget::HerdrCreate, "box_1"),
        ] {
            let (program, args) = target_command(target, session, &binary, &home).unwrap();
            let mut actual = vec![program.as_os_str().to_string_lossy().into_owned()];
            actual.extend(args.iter().map(|arg| arg.to_string_lossy().into_owned()));
            let expected: Vec<String> = argv
                .get(case)
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .unwrap()
                        .replace("<bin>", "/opt/homebrew/bin/tmux")
                        .replace("<home>", "/Users/example")
                })
                .collect();
            assert_eq!(actual, expected, "argv mismatch for {case}");
        }
        // The `=` exact-match prefix is present on tmux attach, and tmux is told the terminal
        // is UTF-8 rather than left to infer it from a locale the daemon does not have.
        // Asserted by content, not by index: the argv gains and loses leading flags.
        let (_, args) = target_command(TerminalTarget::TmuxAttach, "api", &binary, &home).unwrap();
        assert_eq!(args.last().unwrap(), &OsString::from("=api"));
        assert!(
            args.contains(&OsString::from("-u")),
            "without this tmux draws every non-ASCII character as an underscore"
        );

        assert!(matches!(
            target_command(TerminalTarget::TmuxAttach, "bad name", &binary, &home),
            Err(HostProtocolError::InvalidTarget)
        ));
        assert!(matches!(
            target_command(TerminalTarget::Shell, "api", &binary, &home),
            Err(HostProtocolError::UnsupportedTarget)
        ));
    }

    #[tokio::test]
    async fn bounded_exec_enforces_timeout_and_kills_the_child() {
        let directory = tempdir().unwrap();
        let pid_file = directory.path().join("pid");
        let stub = write_stub(
            directory.path(),
            "slow",
            &format!("echo $$ > {}\nsleep 30", pid_file.display()),
        );
        let started = StdInstant::now();
        let result = run_bounded(&stub, &[]).await;
        assert_eq!(result.err(), Some(ProviderExecError::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(5));
        // The child must be SIGKILLed by kill_on_drop; give the runtime a moment to reap it.
        let pid: i32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let mut attempts = 0;
        loop {
            match kill(Pid::from_raw(pid), None) {
                Err(Errno::ESRCH) => break,
                _ if attempts > 40 => panic!("timed-out provider child survived"),
                _ => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    #[tokio::test]
    async fn bounded_exec_caps_output_without_blocking_the_child() {
        let directory = tempdir().unwrap();
        // 128 KiB of stdout and 16 KiB of stderr, both over their caps.
        let stub = write_stub(
            directory.path(),
            "chatty",
            "i=0; while [ $i -lt 32 ]; do printf '%04096d' 7; i=$((i+1)); done; \
             j=0; while [ $j -lt 4 ]; do printf '%04096d' 8 1>&2; j=$((j+1)); done; exit 0",
        );
        let output = run_bounded(&stub, &[]).await.unwrap();
        assert!(output.status_success);
        assert_eq!(output.stdout.len(), PROVIDER_STDOUT_CAP);
        assert_eq!(output.stderr.len(), PROVIDER_STDERR_CAP);
        assert!(output.stdout_truncated);
        assert!(output.stderr_truncated);
    }

    #[tokio::test]
    async fn bounded_exec_uses_the_cleaned_environment_policy() {
        let directory = tempdir().unwrap();
        let stub = write_stub(directory.path(), "env-probe", "env; exit 0");
        let output = run_bounded(&stub, &[]).await.unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        // Cargo always sets CARGO_MANIFEST_DIR for the test process; the cleaned provider
        // environment must not inherit it or any other non-allowlisted variable.
        assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
        assert!(!text.contains("CARGO_MANIFEST_DIR"));
        assert!(text.contains("TERM=xterm-256color"));
        assert!(text.lines().any(|line| line.starts_with("HOME=")));
    }

    #[tokio::test]
    async fn stubbed_snapshot_reports_available_providers_and_omissions() {
        let fixture = fixture();
        let directory = tempdir().unwrap();
        let tmux_list = fixture
            .get("tmux")
            .unwrap()
            .get("list_stdout")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let herdr_list = fixture
            .get("herdr")
            .unwrap()
            .get("list_stdout")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let tmux_payload = directory.path().join("tmux-list.txt");
        fs::write(&tmux_payload, tmux_list).unwrap();
        let herdr_payload = directory.path().join("herdr-list.json");
        fs::write(&herdr_payload, herdr_list).unwrap();
        write_stub(
            directory.path(),
            "tmux",
            &format!(
                "if [ \"$1\" = \"-V\" ]; then echo 'tmux 3.6b'; else cat {}; fi",
                tmux_payload.display()
            ),
        );
        write_stub(
            directory.path(),
            "herdr",
            &format!(
                "if [ \"$1\" = \"--version\" ]; then echo 'herdr 0.7.4'; else cat {}; fi",
                herdr_payload.display()
            ),
        );
        let config = WorkspaceConfig::with_binary_dirs(vec![directory.path().to_owned()]);
        let snapshot = capture_snapshot(&config, None).await;
        assert_eq!(snapshot.providers.tmux.state, PROVIDER_STATE_AVAILABLE);
        assert_eq!(snapshot.providers.tmux.version.as_deref(), Some("3.6b"));
        assert_eq!(snapshot.providers.tmux.sessions.as_ref().unwrap().len(), 2);
        assert_eq!(snapshot.providers.herdr.state, PROVIDER_STATE_AVAILABLE);
        assert_eq!(snapshot.providers.herdr.sessions.as_ref().unwrap().len(), 2);
        // Three tmux violators plus one herdr violator from the fixture.
        assert_eq!(snapshot.omitted_sessions, 4);
        snapshot.validate().unwrap();
    }

    #[tokio::test]
    async fn stubbed_snapshot_maps_provider_failure_modes_categorically() {
        let directory = tempdir().unwrap();
        // tmux exits nonzero with the no-server diagnostic → available and empty.
        write_stub(
            directory.path(),
            "tmux",
            "if [ \"$1\" = \"-V\" ]; then echo 'tmux 3.6b'; else \
             echo 'no server running on /private/tmp/tmux-501/default' 1>&2; exit 1; fi",
        );
        // herdr reports a version below the minimum.
        write_stub(directory.path(), "herdr", "echo 'herdr 0.6.9'");
        let config = WorkspaceConfig::with_binary_dirs(vec![directory.path().to_owned()]);
        let snapshot = capture_snapshot(&config, None).await;
        assert_eq!(snapshot.providers.tmux.state, PROVIDER_STATE_AVAILABLE);
        assert_eq!(snapshot.providers.tmux.sessions.as_deref(), Some(&[][..]));
        assert_eq!(
            snapshot.providers.herdr.state,
            PROVIDER_STATE_UNSUPPORTED_VERSION
        );
        assert_eq!(snapshot.providers.herdr.version.as_deref(), Some("0.6.9"));
        snapshot.validate().unwrap();

        // Missing binaries → not_installed; the snapshot itself never fails.
        let empty = tempdir().unwrap();
        let config = WorkspaceConfig::with_binary_dirs(vec![empty.path().to_owned()]);
        let snapshot = capture_snapshot(&config, None).await;
        assert_eq!(snapshot.providers.tmux.state, PROVIDER_STATE_NOT_INSTALLED);
        assert_eq!(snapshot.providers.herdr.state, PROVIDER_STATE_NOT_INSTALLED);
        assert!(snapshot.providers.tmux.version.is_none());
        snapshot.validate().unwrap();

        // A failing list command that is not the no-server case → categorical error state.
        let failing = tempdir().unwrap();
        write_stub(
            failing.path(),
            "tmux",
            "if [ \"$1\" = \"-V\" ]; then echo 'tmux 3.6b'; else \
             echo 'permission denied /some/private/path' 1>&2; exit 1; fi",
        );
        let config = WorkspaceConfig::with_binary_dirs(vec![failing.path().to_owned()]);
        let snapshot = capture_snapshot(&config, None).await;
        assert_eq!(snapshot.providers.tmux.state, PROVIDER_STATE_ERROR);
        // The categorical error state carries no stderr content anywhere in the result.
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert!(!encoded.contains("permission denied"));
        assert!(!encoded.contains("/some/private/path"));
    }

    #[tokio::test]
    async fn snapshot_budget_bounds_a_hung_provider() {
        let directory = tempdir().unwrap();
        // Version probes answer instantly, then the tmux listing hangs longer than the
        // per-exec timeout twice over; herdr stays healthy and must still report.
        write_stub(
            directory.path(),
            "tmux",
            "if [ \"$1\" = \"-V\" ]; then echo 'tmux 3.6b'; else sleep 30; fi",
        );
        write_stub(
            directory.path(),
            "herdr",
            "if [ \"$1\" = \"--version\" ]; then echo 'herdr 0.7.4'; else \
             echo '{\"sessions\":[]}'; fi",
        );
        let config = WorkspaceConfig::with_binary_dirs(vec![directory.path().to_owned()]);
        let started = StdInstant::now();
        let snapshot = capture_snapshot(&config, None).await;
        assert!(started.elapsed() <= SNAPSHOT_BUDGET + Duration::from_secs(1));
        assert_eq!(snapshot.providers.tmux.state, PROVIDER_STATE_ERROR);
        assert_eq!(snapshot.providers.herdr.state, PROVIDER_STATE_AVAILABLE);
        snapshot.validate().unwrap();
    }

    /// The handback argv is the whole security boundary of this feature: a vendor ID reaching
    /// a shell would be a command-injection surface, so it never becomes a string a shell
    /// reads. These assertions pin the argv exactly, and pin the refusals that keep it that way.
    #[test]
    fn handback_argv_is_fixed_and_refuses_anything_it_cannot_vouch_for() {
        let ok = HandbackRequest {
            session: "ciao-proj-abc123def456",
            workspace: "/Users/someone/proj",
            tool_path: "/opt/homebrew/bin:/usr/bin",
            cli: "/opt/sdk/claude",
            vendor_session: "6d169dac-12a2-4cd5-a9c3-5b45ddfdb63b",
        };
        assert_eq!(
            handback_argv(&ok).expect("a well-formed handback builds"),
            vec![
                "-u",
                "new-session",
                "-d",
                "-s",
                "ciao-proj-abc123def456",
                "-c",
                "/Users/someone/proj",
                "/usr/bin/env",
                "PATH=/opt/homebrew/bin:/usr/bin",
                "/opt/sdk/claude",
                "--resume",
                "6d169dac-12a2-4cd5-a9c3-5b45ddfdb63b",
            ]
        );
        // `-A` would adopt an existing session instead of failing, which is how a handback
        // could silently land in a terminal running something else entirely.
        assert!(!handback_argv(&ok).unwrap().iter().any(|arg| arg == "-A"));

        let refuses = |mutate: &dyn Fn(&mut HandbackRequest<'_>)| {
            let mut request = HandbackRequest { ..ok };
            mutate(&mut request);
            handback_argv(&request).is_none()
        };
        assert!(refuses(&|r| r.session = "not a session name"));
        assert!(refuses(&|r| r.vendor_session = "$(rm -rf ~)"));
        assert!(refuses(&|r| r.vendor_session = "one two"));
        assert!(refuses(&|r| r.vendor_session = ""));
        assert!(refuses(&|r| r.workspace = "relative/path"));
        assert!(refuses(&|r| r.cli = "claude"));
    }

    /// The name is what someone reads in `tmux ls` while looking for where their conversation
    /// went, so it carries the workspace — but it must satisfy the provider grammar whatever
    /// the workspace was called.
    #[test]
    fn handback_session_names_stay_legible_and_valid() {
        let name = handback_session_name("my.project", "abc123def456789").unwrap();
        assert_eq!(name, "ciao-my-project-abc123def456");
        assert!(valid_session_name(&name));

        let awkward = handback_session_name("../../etc", "0011223344556677").unwrap();
        assert!(valid_session_name(&awkward), "{awkward}");
        assert!(!awkward.contains('/') && !awkward.contains('.'));

        let unnamed = handback_session_name("", "0011223344556677").unwrap();
        assert!(valid_session_name(&unnamed));

        // A workspace label long enough to overrun the grammar is truncated, not rejected.
        let long = handback_session_name(&"w".repeat(200), "0011223344556677").unwrap();
        assert!(valid_session_name(&long), "{long}");

        // Nothing usable to name it with is a refusal, not a session called "ciao-".
        assert!(handback_session_name("proj", "!!!!").is_none());
    }

    fn tabs_fixture() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase8/workspace-tabs-v1.json"
        );
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn plain_tmux_session(name: &str) -> TmuxSessionEntry {
        TmuxSessionEntry {
            name: name.to_owned(),
            attached: false,
            windows: 1,
            created_unix: 1_789_000_000,
            tabs: None,
        }
    }

    #[test]
    fn tmux_window_listing_parses_the_spaced_format_and_drops_what_it_cannot_vouch_for() {
        let fixture = tabs_fixture();
        let stdout = fixture
            .get("tmux_window_list_stdout")
            .unwrap()
            .as_str()
            .unwrap();
        let sessions = vec![plain_tmux_session("api"), plain_tmux_session("lab")];
        let windows = parse_tmux_window_list(stdout.as_bytes(), &sessions);

        let api = windows.get("api").unwrap();
        assert_eq!(
            api.iter().map(|tab| tab.id.as_str()).collect::<Vec<_>>(),
            vec!["@1", "@2", "@5"],
            "windows keep index order"
        );
        assert_eq!(api[1].label, "two words here");
        assert!(api[1].focused);
        assert!(!api[0].focused);
        // An empty window name falls back to the window index, never an empty label.
        assert_eq!(api[2].label, "7");
        assert!(api.iter().all(|tab| tab.status.is_none()));

        let lab = windows.get("lab").unwrap();
        assert_eq!(lab.len(), 1);
        assert_eq!(lab[0].label, "sleep");

        // The `ghost` session is not in the snapshot, and the garbage line has no window id;
        // both vanish alone without disturbing what parsed.
        assert_eq!(windows.len(), 2);
    }

    #[test]
    fn herdr_tab_listing_parses_the_probe_envelope_and_drops_violators_alone() {
        let fixture = tabs_fixture();
        let stdout = fixture
            .get("herdr_tab_list_stdout")
            .unwrap()
            .as_str()
            .unwrap();
        let tabs = parse_herdr_tab_list(stdout.as_bytes()).unwrap();
        // Four tabs in the document; the one whose id has a space is dropped alone.
        assert_eq!(
            tabs.iter().map(|tab| tab.id.as_str()).collect::<Vec<_>>(),
            vec!["wV:tC", "wX:t19", "wX:t8"]
        );
        assert_eq!(tabs[1].label, "example-lab");
        assert!(tabs[1].focused);
        assert_eq!(tabs[1].status.as_deref(), Some("working"));
        assert_eq!(tabs[2].status.as_deref(), Some("unknown"));

        // The error envelope (`server_not_running` from the live probe) is no tabs at all.
        let error = fixture
            .get("herdr_tab_list_error_stdout")
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(parse_herdr_tab_list(error.as_bytes()), None);

        // Undecodable, oversized, and over-deep documents are all refused the same way.
        assert_eq!(parse_herdr_tab_list(b"not json"), None);
        let oversized = vec![b' '; HERDR_JSON_MAX_BYTES + 1];
        assert_eq!(parse_herdr_tab_list(&oversized), None);
        let deep = br#"{"result":{"tabs":[{"nested":{"too":"far"}}]}}"#;
        assert_eq!(parse_herdr_tab_list(deep), None);
    }

    #[test]
    fn herdr_workspace_labels_resolve_onto_tabs_and_collapse_when_they_say_nothing() {
        let fixture = tabs_fixture();
        let stdout = fixture
            .get("herdr_workspace_list_stdout")
            .unwrap()
            .as_str()
            .unwrap();
        let labels = parse_herdr_workspace_labels(stdout.as_bytes()).unwrap();
        // Five workspaces in the document: the one whose id has a space and the one with an
        // empty label are dropped alone, and the one padded with whitespace around a control
        // byte is sanitized rather than carried to a phone.
        let mut named: Vec<(&str, &str)> = labels
            .iter()
            .map(|(id, label)| (id.as_str(), label.as_str()))
            .collect();
        named.sort();
        assert_eq!(
            named,
            vec![("wV", "example-api"), ("wX", "iroh"), ("wZ", "unused")]
        );

        let tabs = parse_herdr_tab_list(
            fixture
                .get("herdr_tab_list_stdout")
                .unwrap()
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        // Straight out of the parse the field holds the *id*; only `resolve_workspaces` may
        // put a label there, and only one that the workspace listing named.
        assert_eq!(
            tabs.iter()
                .map(|tab| tab.workspace.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("wV"), Some("wX"), Some("wX")]
        );
        let resolved = resolve_workspaces(tabs.clone(), labels.clone());
        assert_eq!(
            resolved
                .iter()
                .map(|tab| tab.workspace.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("example-api"), Some("iroh"), Some("iroh")]
        );

        // One workspace across every tab is a header drawn over the whole list, which is not
        // information — the level collapses rather than repeating itself.
        let single: std::collections::HashMap<String, String> =
            [("wV".to_owned(), "example-api".to_owned())]
                .into_iter()
                .collect();
        assert!(
            resolve_workspaces(tabs.clone(), single)
                .iter()
                .all(|tab| tab.workspace.is_none())
        );

        // A failed or undecodable listing leaves the tabs exactly as they were before the
        // workspace level existed.
        assert!(
            resolve_workspaces(tabs, Default::default())
                .iter()
                .all(|tab| tab.workspace.is_none())
        );

        let error = fixture
            .get("herdr_workspace_list_error_stdout")
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(parse_herdr_workspace_labels(error.as_bytes()), None);
        assert_eq!(parse_herdr_workspace_labels(b"not json"), None);
        let oversized = vec![b' '; HERDR_JSON_MAX_BYTES + 1];
        assert_eq!(parse_herdr_workspace_labels(&oversized), None);
    }

    #[test]
    fn tab_normalization_enforces_the_wire_invariants() {
        let tab = |id: usize, focused: bool| SessionTabEntry {
            id: format!("w0:t{id}"),
            label: format!("tab-{id}"),
            focused,
            status: None,
            agent_session_id: None,
            workspace: None,
        };
        let overfull: Vec<SessionTabEntry> = (0..MAX_TABS_PER_SESSION + 3)
            .map(|index| tab(index, false))
            .collect();
        assert_eq!(
            normalize_tabs(overfull).unwrap().len(),
            MAX_TABS_PER_SESSION
        );

        // Provider drift marking two tabs focused must not invalidate the snapshot; the
        // builder keeps the first claim and clears the rest.
        let double = vec![tab(0, true), tab(1, true), tab(2, false)];
        let normalized = normalize_tabs(double).unwrap();
        assert_eq!(
            normalized.iter().filter(|tab| tab.focused).count(),
            1,
            "exactly one focused survives"
        );
        assert!(normalized[0].focused);

        assert_eq!(normalize_tabs(Vec::new()), None);
    }

    #[test]
    fn tab_labels_are_sanitized_bounded_and_never_empty() {
        assert_eq!(
            sanitize_tab_label("a\u{7}b\u{1b}[31m"),
            Some("ab[31m".into())
        );
        assert_eq!(sanitize_tab_label("   "), None);
        assert_eq!(sanitize_tab_label("\u{7}\u{8}"), None);
        assert_eq!(sanitize_tab_label("  keep  "), Some("keep".into()));
        // Multibyte truncation lands on a char boundary, never a partial sequence.
        let wide = "é".repeat(40);
        let label = sanitize_tab_label(&wide).unwrap();
        assert!(label.len() <= MAX_TAB_LABEL_BYTES);
        assert_eq!(label.chars().count(), MAX_TAB_LABEL_BYTES / 2);
    }

    #[tokio::test]
    async fn focus_tab_builds_the_exact_scoped_argv_and_reads_the_envelope() {
        let directory = tempdir().unwrap();
        let log = directory.path().join("argv.log");
        write_stub(
            directory.path(),
            "tmux",
            &format!("printf '%s' \"$*\" > {}; exit 0", log.display()),
        );
        write_stub(
            directory.path(),
            "herdr",
            &format!(
                "printf '%s' \"$*\" > {}; echo '{{\"id\":\"cli:tab:focus\",\"result\":{{}}}}'",
                log.display()
            ),
        );
        let config = WorkspaceConfig::with_binary_dirs(vec![directory.path().to_owned()]);

        assert!(focus_tab(&config, ProviderKind::Tmux, "api", "@3").await);
        assert_eq!(
            fs::read_to_string(&log).unwrap(),
            "select-window -t =api:@3",
            "the scoped form validates membership for free"
        );

        assert!(focus_tab(&config, ProviderKind::Herdr, "boxes", "wX:t19").await);
        assert_eq!(
            fs::read_to_string(&log).unwrap(),
            "--session boxes tab focus wX:t19"
        );

        // A herdr-shaped id on the tmux path is refused before any process spawns.
        fs::remove_file(&log).unwrap();
        assert!(!focus_tab(&config, ProviderKind::Tmux, "api", "wX:t19").await);
        assert!(!focus_tab(&config, ProviderKind::Herdr, "boxes", "ha sh").await);
        assert!(!focus_tab(&config, ProviderKind::Herdr, "=boxes", "wX:t19").await);
        assert!(!log.exists(), "refusals never reach the provider");

        // herdr reports API failures as an error envelope on a zero exit; that envelope is
        // the truth, not the exit code.
        write_stub(
            directory.path(),
            "herdr",
            "echo '{\"id\":\"cli:tab:focus\",\"error\":{\"code\":\"tab_not_found\"}}'",
        );
        assert!(!focus_tab(&config, ProviderKind::Herdr, "boxes", "wX:t99").await);
    }

    /// Spec 015 §11.1: the directory a relative preview token resolves against comes from the
    /// multiplexer, because the shell never reports one. Both providers are asked with an
    /// exact-name scope, and herdr's foreground directory outranks the pane's own.
    #[tokio::test]
    async fn session_cwd_asks_each_provider_with_an_exact_scope_and_prefers_the_foreground() {
        let directory = tempdir().unwrap();
        let log = directory.path().join("argv.log");
        write_stub(
            directory.path(),
            "tmux",
            &format!(
                "printf '%s' \"$*\" > {}; printf '/Users/o/Developer/ciao\\n'",
                log.display()
            ),
        );
        write_stub(
            directory.path(),
            "herdr",
            &format!(
                "printf '%s' \"$*\" > {}; echo '{{\"result\":{{\"pane\":{{\"cwd\":\"/shell/dir\",\"foreground_cwd\":\"/agent/dir\"}}}}}}'",
                log.display()
            ),
        );
        let config = WorkspaceConfig::with_binary_dirs(vec![directory.path().to_owned()]);

        assert_eq!(
            session_cwd(&config, ProviderKind::Tmux, "api")
                .await
                .as_deref(),
            Some("/Users/o/Developer/ciao"),
            "the trailing newline tmux prints is not part of the directory"
        );
        assert_eq!(
            fs::read_to_string(&log).unwrap(),
            "display -p -t =api: #{pane_current_path}",
            "`=name` scopes to an exact session; the trailing colon is what makes it a pane, \
             and without it tmux answers nothing on a zero exit"
        );

        assert_eq!(
            session_cwd(&config, ProviderKind::Herdr, "boxes")
                .await
                .as_deref(),
            Some("/agent/dir"),
            "the path on screen was printed by the foreground program, not by the shell"
        );
        assert_eq!(
            fs::read_to_string(&log).unwrap(),
            "--session boxes pane current"
        );

        // An invalid session name is refused before any process spawns.
        fs::remove_file(&log).unwrap();
        assert_eq!(
            session_cwd(&config, ProviderKind::Herdr, "=boxes").await,
            None
        );
        assert!(!log.exists(), "refusals never reach the provider");
    }

    /// A provider answer is input: only an absolute path may become the base a relative token is
    /// joined to. Everything else is dropped, so the preview refuses instead of resolving
    /// against somewhere nobody is looking.
    #[tokio::test]
    async fn session_cwd_discards_an_answer_that_is_not_an_absolute_path() {
        let directory = tempdir().unwrap();
        let config = WorkspaceConfig::with_binary_dirs(vec![directory.path().to_owned()]);

        for script in [
            "printf 'relative/dir\\n'", // not absolute
            "printf '\\n'",             // empty
            "exit 1",                   // no such session
            "printf '/fine'; exit 1",   // a path, but the command failed
        ] {
            write_stub(directory.path(), "tmux", script);
            assert_eq!(
                session_cwd(&config, ProviderKind::Tmux, "api").await,
                None,
                "rejected: {script}"
            );
        }

        // herdr answering with its error envelope has no `result.pane` to read.
        write_stub(
            directory.path(),
            "herdr",
            "echo '{\"id\":\"cli:pane:current\",\"error\":{\"code\":\"no_session\"}}'",
        );
        assert_eq!(
            session_cwd(&config, ProviderKind::Herdr, "gone").await,
            None
        );
    }

    /// The same call that answers "where" answers "what is running there". Only herdr does:
    /// tmux's foreground command is a process *name*, and Claude Code wears its version string
    /// as one, so tmux is left saying nothing rather than saying something a caller would gate
    /// a feature on.
    #[tokio::test]
    async fn pane_facts_carries_herdrs_agent_and_leaves_tmux_saying_nothing() {
        let directory = tempdir().unwrap();
        let config = WorkspaceConfig::with_binary_dirs(vec![directory.path().to_owned()]);

        write_stub(
            directory.path(),
            "herdr",
            "echo '{\"result\":{\"pane\":{\"agent\":\"claude\",\"cwd\":\"/shell/dir\",\"foreground_cwd\":\"/agent/dir\"}}}'",
        );
        assert_eq!(
            pane_facts(&config, ProviderKind::Herdr, "boxes").await,
            PaneFacts {
                cwd: Some("/agent/dir".into()),
                agent: Some("claude".into()),
            }
        );

        // tmux still answers the directory; the agent stays absent by construction.
        write_stub(directory.path(), "tmux", "printf '/Users/o/ciao\\n'");
        assert_eq!(
            pane_facts(&config, ProviderKind::Tmux, "api").await,
            PaneFacts {
                cwd: Some("/Users/o/ciao".into()),
                agent: None,
            },
            "a name-shaped guess here would gate the picker on a semver-shaped string"
        );

        // A pane with no agent in it is the ordinary shell case, and it is not a failure.
        write_stub(
            directory.path(),
            "herdr",
            "echo '{\"result\":{\"pane\":{\"foreground_cwd\":\"/agent/dir\"}}}'",
        );
        assert_eq!(
            pane_facts(&config, ProviderKind::Herdr, "boxes")
                .await
                .agent,
            None
        );

        // The directory and the agent fail independently: an agent worth reporting survives a
        // directory that is not reportable.
        write_stub(
            directory.path(),
            "herdr",
            "echo '{\"result\":{\"pane\":{\"agent\":\"codex\",\"cwd\":\"relative/dir\"}}}'",
        );
        assert_eq!(
            pane_facts(&config, ProviderKind::Herdr, "boxes").await,
            PaneFacts {
                cwd: None,
                agent: Some("codex".into()),
            }
        );

        // A provider name is input. Anything outside the bounded lowercase vocabulary is
        // dropped rather than carried to a match arm and a phone.
        for hostile in [
            "\\\"Claude\\\"",  // upper case
            "\\\"cl aude\\\"", // a space
            "\\\"\\\"",        // empty
        ] {
            write_stub(
                directory.path(),
                "herdr",
                &format!(
                    "echo '{{\"result\":{{\"pane\":{{\"agent\":{hostile},\"foreground_cwd\":\"/d\"}}}}}}'"
                ),
            );
            assert_eq!(
                pane_facts(&config, ProviderKind::Herdr, "boxes")
                    .await
                    .agent,
                None,
                "rejected: {hostile}"
            );
        }
    }

    #[tokio::test]
    async fn stubbed_snapshot_carries_tabs_only_when_asked_and_never_degrades_without_them() {
        let fixture = tabs_fixture();
        let directory = tempdir().unwrap();
        let queries = directory.path().join("tab-queries.log");

        let tmux_windows = directory.path().join("windows.txt");
        fs::write(
            &tmux_windows,
            fixture
                .get("tmux_window_list_stdout")
                .unwrap()
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let tmux_list = directory.path().join("tmux-list.txt");
        fs::write(
            &tmux_list,
            "api\u{1f}1\u{1f}3\u{1f}1789000000\nlab\u{1f}0\u{1f}1\u{1f}1789000500\n",
        )
        .unwrap();
        write_stub(
            directory.path(),
            "tmux",
            &format!(
                "if [ \"$1\" = \"-V\" ]; then echo 'tmux 3.7b'; \
                 elif [ \"$1\" = \"list-windows\" ]; then cat {}; \
                 else cat {}; fi",
                tmux_windows.display(),
                tmux_list.display()
            ),
        );

        let herdr_sessions = directory.path().join("herdr-list.json");
        fs::write(
            &herdr_sessions,
            r#"{"sessions":[{"name":"default","running":true,"default":true},{"name":"boxes","running":true,"default":false},{"name":"stopped","running":false,"default":false}]}"#,
        )
        .unwrap();
        let boxes_tabs = directory.path().join("boxes-tabs.json");
        fs::write(
            &boxes_tabs,
            fixture
                .get("herdr_tab_list_stdout")
                .unwrap()
                .as_str()
                .unwrap(),
        )
        .unwrap();
        // `default`'s tab listing fails outright: the failure path must leave that session
        // exactly as a no-tabs snapshot would.
        let boxes_workspaces = directory.path().join("boxes-workspaces.json");
        fs::write(
            &boxes_workspaces,
            fixture
                .get("herdr_workspace_list_stdout")
                .unwrap()
                .as_str()
                .unwrap(),
        )
        .unwrap();
        write_stub(
            directory.path(),
            "herdr",
            &format!(
                "if [ \"$1\" = \"--version\" ]; then echo 'herdr 0.8.0'; \
                 elif [ \"$1\" = \"--session\" ]; then echo \"$2 $3\" >> {}; \
                 if [ \"$2\" != \"boxes\" ]; then exit 1; \
                 elif [ \"$3\" = \"workspace\" ]; then cat {}; else cat {}; fi; \
                 else cat {}; fi",
                queries.display(),
                boxes_workspaces.display(),
                boxes_tabs.display(),
                herdr_sessions.display()
            ),
        );

        let config = WorkspaceConfig::with_binary_dirs(vec![directory.path().to_owned()]);
        let with_tabs = capture_snapshot(&config, Some(&Default::default())).await;
        with_tabs.validate().unwrap();

        let tmux = with_tabs.providers.tmux.sessions.as_ref().unwrap();
        assert_eq!(tmux[0].name, "api");
        let api_tabs = tmux[0].tabs.as_ref().unwrap();
        assert_eq!(api_tabs.len(), 3);
        assert_eq!(api_tabs[1].label, "two words here");
        assert_eq!(tmux[1].tabs.as_ref().unwrap()[0].label, "sleep");

        let herdr = with_tabs.providers.herdr.sessions.as_ref().unwrap();
        assert_eq!(herdr[0].name, "default");
        assert_eq!(herdr[0].tabs, None, "a failed tab listing is just no tabs");
        let boxes = herdr[1].tabs.as_ref().unwrap();
        assert_eq!(boxes.len(), 3);
        assert_eq!(boxes[1].status.as_deref(), Some("working"));
        // The workspace level herdr actually has: the tab's `workspace_id` resolved to the
        // workspace's *label*, sanitized on the way through, and never the id itself.
        assert_eq!(
            boxes
                .iter()
                .map(|tab| tab.workspace.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("example-api"), Some("iroh"), Some("iroh")]
        );
        assert_eq!(herdr[2].tabs, None);
        // tmux has no such level and must never grow one.
        assert!(api_tabs.iter().all(|tab| tab.workspace.is_none()));

        // Only the running sessions were ever asked; the stopped one has no socket to answer.
        // Each running one is asked for both listings, because one call cannot answer both.
        let mut asked: Vec<String> = fs::read_to_string(&queries)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        asked.sort();
        assert_eq!(
            asked,
            vec![
                "boxes tab",
                "boxes workspace",
                "default tab",
                "default workspace"
            ]
        );

        // A legacy request produces the same snapshot minus every tab — nothing else moved.
        let without_tabs = capture_snapshot(&config, None).await;
        without_tabs.validate().unwrap();
        let mut stripped = with_tabs.clone();
        if let Some(sessions) = stripped.providers.tmux.sessions.as_mut() {
            for session in sessions {
                session.tabs = None;
            }
        }
        if let Some(sessions) = stripped.providers.herdr.sessions.as_mut() {
            for session in sessions {
                session.tabs = None;
            }
        }
        assert_eq!(stripped, without_tabs);

        // The join itself: an index naming one pane per provider annotates exactly those tabs.
        // Keyed by (provider, session, tab), so an index entry whose session or tab does not
        // exist annotates nothing rather than landing on a neighbour.
        let mut agents = AgentTabIndex::new();
        agents.insert(
            (ProviderKind::Tmux, "api".into(), "@2".into()),
            "session-a".into(),
        );
        agents.insert(
            (ProviderKind::Herdr, "boxes".into(), "wX:t19".into()),
            "session-b".into(),
        );
        // Same tab id under the wrong session, and the right session under the wrong provider.
        // Both must miss: tmux window ids and herdr tab ids share no namespace, but a join keyed
        // on the tab alone would still collide across sessions.
        agents.insert(
            (ProviderKind::Tmux, "lab".into(), "@2".into()),
            "session-wrong-session".into(),
        );
        agents.insert(
            (ProviderKind::Herdr, "api".into(), "@1".into()),
            "session-wrong-provider".into(),
        );

        let joined = capture_snapshot(&config, Some(&agents)).await;
        joined.validate().unwrap();
        let tmux = joined.providers.tmux.sessions.as_ref().unwrap();
        let api_tabs = tmux[0].tabs.as_ref().unwrap();
        assert_eq!(api_tabs[1].id, "@2");
        assert_eq!(api_tabs[1].agent_session_id.as_deref(), Some("session-a"));
        assert_eq!(api_tabs[0].agent_session_id, None);
        assert_eq!(api_tabs[2].agent_session_id, None);
        // `lab` has no `@2`, so the deliberately wrong entry annotated nothing at all.
        assert!(
            tmux[1]
                .tabs
                .as_ref()
                .unwrap()
                .iter()
                .all(|tab| tab.agent_session_id.is_none())
        );
        let boxes = joined.providers.herdr.sessions.as_ref().unwrap()[1]
            .tabs
            .as_ref()
            .unwrap();
        assert_eq!(boxes[1].id, "wX:t19");
        assert_eq!(boxes[1].agent_session_id.as_deref(), Some("session-b"));
        assert_eq!(boxes[0].agent_session_id, None);
        assert_eq!(boxes[2].agent_session_id, None);

        // Annotation is the only difference an index makes. Everything else about the snapshot
        // — sessions, labels, focus, status, ordering — is identical to the empty-index run.
        let mut bare = joined.clone();
        for session in bare.providers.tmux.sessions.as_mut().unwrap() {
            for tab in session.tabs.as_mut().into_iter().flatten() {
                tab.agent_session_id = None;
            }
        }
        for session in bare.providers.herdr.sessions.as_mut().unwrap() {
            for tab in session.tabs.as_mut().into_iter().flatten() {
                tab.agent_session_id = None;
            }
        }
        assert_eq!(bare, with_tabs);
    }
}
