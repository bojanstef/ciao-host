//! Host-only exact terminal-route proof for attached Agent Sessions (Spec 005 §10).
//!
//! Provider identifiers, process topology, paths, and argv never cross this boundary. Every
//! provider operation uses a resolved fixed binary plus a fixed argument vocabulary.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::Value;
use tokio::time::timeout;

use crate::{
    agent_protocol::{MAX_OPAQUE_ID_BYTES, valid_opaque_id},
    host_protocol::{ProviderKind, valid_session_name, valid_tab_id},
    process,
    workspace::{
        WorkspaceConfig, focus_tab, parse_herdr_tab_list, run_bounded, sanitize_tab_label,
    },
};

const ROUTE_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(5);
const TMUX_ROUTE_FORMAT: &str = "#{session_name}\u{1f}#{session_id}\u{1f}#{window_id}\u{1f}#{pane_id}\u{1f}#{pane_pid}\u{1f}#{pane_tty}";
const MAX_HERDR_PANES: usize = 64;
const UNIT_SEPARATOR: char = '\u{1f}';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteContinuity {
    ExactLive,
    WorkspaceOnly,
}

impl RouteContinuity {
    pub(crate) const fn wire(self) -> &'static str {
        match self {
            Self::ExactLive => "exact_live",
            Self::WorkspaceOnly => "workspace_only",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentRouteProof {
    Tmux {
        binary: PathBuf,
        bridge_pid: u32,
        /// The session as the workspace snapshot names it. tmux's own `$N` id is what the route
        /// operates on; this is only how a tab row refers to the same session, so — exactly like
        /// `tab_id` below — it is deliberately absent from `revalidate`. A renamed session is
        /// still the pane the agent is in.
        session_name: String,
        session_id: String,
        window_id: String,
        pane_id: String,
        pane_pid: u32,
        pane_tty: String,
    },
    HerdrWorkspace {
        binary: PathBuf,
        bridge_pid: u32,
        session_name: String,
        pane_id: String,
        terminal_id: String,
        /// The tab owning `pane_id`, straight off the same snapshot row. Not part of the proof's
        /// identity — a tab can be renamed or the pane moved between tabs without the route going
        /// stale — so it is deliberately absent from `revalidate` and used only to aim the attach.
        tab_id: Option<String>,
    },
}

impl AgentRouteProof {
    pub(crate) const fn continuity(&self) -> RouteContinuity {
        match self {
            Self::Tmux { .. } => RouteContinuity::ExactLive,
            Self::HerdrWorkspace { .. } => RouteContinuity::WorkspaceOnly,
        }
    }

    /// How a workspace snapshot's tab row refers to this pane: provider, session name, tab id.
    /// tmux windows *are* the tab rows (`@N`), and herdr names its own tab, so both sides of the
    /// join already speak the same vocabulary — see `parse_tmux_window_list` and `parse_herdr_tabs`.
    ///
    /// `None` when the proof cannot name a tab, which is a herdr pane whose snapshot row carried
    /// no `tab_id`. A route is still perfectly good for attaching; it simply cannot be pointed at
    /// from the tab list, and the caller must leave that tab unannotated rather than guess.
    pub(crate) fn tab_key(&self) -> Option<(ProviderKind, String, String)> {
        match self {
            Self::Tmux {
                session_name,
                window_id,
                ..
            } => Some((ProviderKind::Tmux, session_name.clone(), window_id.clone())),
            Self::HerdrWorkspace {
                session_name,
                tab_id,
                ..
            } => tab_id
                .as_ref()
                .map(|tab| (ProviderKind::Herdr, session_name.clone(), tab.clone())),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AgentTerminalPlan {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<OsString>,
    pub(crate) provider: ProviderKind,
}

#[derive(Debug, Clone)]
pub(crate) struct TerminalRouteResolver {
    workspace: WorkspaceConfig,
}

impl TerminalRouteResolver {
    pub(crate) fn new(workspace: WorkspaceConfig) -> Self {
        Self { workspace }
    }

    /// The tab's own name, so an alert can say which of four conversations in one project
    /// wants something. The workspace cannot: all four of them are the same directory.
    ///
    /// Read live rather than carried on the proof, because a tab is renamed far more often than
    /// a route goes stale — the label is display text, never routing data, and deliberately
    /// absent from `revalidate` for exactly that reason. Every failure is `None`: a notification
    /// that cannot name the tab says the workspace instead, which is what it said before.
    ///
    /// Only the notification path calls this, and the notify gate caps that at twelve alerts per
    /// ten minutes. A coalesced alert pays for a lookup it will not use, which is one bounded
    /// provider call an hour in the worst case and not worth a cache that could go stale.
    pub(crate) async fn tab_label(&self, proof: &AgentRouteProof) -> Option<String> {
        match proof {
            AgentRouteProof::Tmux {
                binary, window_id, ..
            } => {
                // Re-validated before argv, the way `target_command` re-validates a session name:
                // a proof is minted from provider output, and this is the last gate before it.
                if !valid_tmux_id(window_id, '@') {
                    return None;
                }
                // A tmux window *is* the tab row, and its id is globally unique, so this
                // needs neither the session nor the whole listing.
                let output = run_bounded(
                    binary,
                    &["display-message", "-p", "-t", window_id, "#{window_name}"],
                )
                .await
                .ok()?;
                if !output.status_success || output.stdout_truncated {
                    return None;
                }
                sanitize_tab_label(String::from_utf8_lossy(&output.stdout).trim())
            }
            AgentRouteProof::HerdrWorkspace {
                binary,
                session_name,
                tab_id,
                ..
            } => {
                let tab_id = tab_id.as_deref()?;
                if !valid_session_name(session_name) {
                    return None;
                }
                let output = run_bounded(binary, &["--session", session_name, "tab", "list"])
                    .await
                    .ok()?;
                if !output.status_success || output.stdout_truncated {
                    return None;
                }
                // The snapshot's own parser, so a label reaching a lock screen is sanitized
                // and bounded by the same rule that governs one reaching the tab list.
                parse_herdr_tab_list(&output.stdout)?
                    .into_iter()
                    .find(|tab| tab.id == tab_id)
                    // That parser falls back to the tab **id** for an unnamed tab, which is
                    // routing data and says nothing on a lock screen. The workspace is better.
                    .filter(|tab| tab.label != tab.id)
                    .map(|tab| tab.label)
            }
        }
    }

    /// Resolves only from the authenticated local bridge PID. tmux wins when providers are
    /// nested because it is the only physically qualified exact-live route in this phase.
    pub(crate) async fn resolve(&self, bridge_pid: u32) -> Option<AgentRouteProof> {
        if bridge_pid == 0 || !process::exists(bridge_pid) {
            return None;
        }
        timeout(ROUTE_RESOLUTION_TIMEOUT, async {
            if let Some(proof) = self.resolve_tmux(bridge_pid).await {
                return Some(proof);
            }
            self.resolve_herdr_workspace(bridge_pid).await
        })
        .await
        .ok()
        .flatten()
    }

    pub(crate) async fn revalidate(&self, proof: &AgentRouteProof) -> bool {
        timeout(ROUTE_RESOLUTION_TIMEOUT, async {
            match proof {
                AgentRouteProof::Tmux {
                    binary,
                    bridge_pid,
                    session_id,
                    window_id,
                    pane_id,
                    pane_pid,
                    pane_tty,
                    // `session_name` is deliberately not compared: see the field's own note.
                    ..
                } => {
                    process::exists(*bridge_pid)
                        && process_tty(*bridge_pid).await.as_deref() == Some(pane_tty)
                        && process::descends_from(*bridge_pid, *pane_pid).await
                        && list_tmux_panes(binary).await.iter().any(|pane| {
                            pane.session_id == *session_id
                                && pane.window_id == *window_id
                                && pane.pane_id == *pane_id
                                && pane.pane_pid == *pane_pid
                                && pane.pane_tty == *pane_tty
                        })
                }
                AgentRouteProof::HerdrWorkspace {
                    binary,
                    bridge_pid,
                    session_name,
                    pane_id,
                    terminal_id,
                    ..
                } => {
                    process::exists(*bridge_pid)
                        && herdr_process_matches(
                            binary,
                            session_name,
                            pane_id,
                            terminal_id,
                            *bridge_pid,
                        )
                        .await
                }
            }
        })
        .await
        .unwrap_or(false)
    }

    /// Revalidates immediately, then performs only the fixed focus operation needed for an exact
    /// route. A stale route never degrades silently to a session-level target.
    pub(crate) async fn terminal_plan(&self, proof: &AgentRouteProof) -> Option<AgentTerminalPlan> {
        if !self.revalidate(proof).await {
            return None;
        }
        match proof {
            AgentRouteProof::Tmux {
                binary,
                session_id,
                window_id,
                pane_id,
                ..
            } => {
                let selected_window = run_bounded(binary, &["select-window", "-t", window_id])
                    .await
                    .is_ok_and(|output| output.status_success);
                let selected_pane = selected_window
                    && run_bounded(binary, &["select-pane", "-t", pane_id])
                        .await
                        .is_ok_and(|output| output.status_success);
                if !selected_pane || !self.revalidate(proof).await {
                    return None;
                }
                Some(AgentTerminalPlan {
                    program: binary.clone(),
                    args: vec!["attach-session".into(), "-t".into(), session_id.into()],
                    provider: ProviderKind::Tmux,
                })
            }
            AgentRouteProof::HerdrWorkspace {
                binary,
                session_name,
                tab_id,
                ..
            } => {
                // Best-effort, exactly like Spec 021's pre-focus before a tapped tab row's attach,
                // and for the same reason: this route's continuity is `WorkspaceOnly`, so the
                // promise is the session. Landing on the agent's own tab is the whole point of
                // following a notification, but a tab closed or moved since the proof was minted
                // lands on the session's current tab rather than refusing the attach outright.
                if let Some(tab_id) = tab_id {
                    focus_tab(&self.workspace, ProviderKind::Herdr, session_name, tab_id).await;
                }
                Some(AgentTerminalPlan {
                    program: binary.clone(),
                    args: vec!["session".into(), "attach".into(), session_name.into()],
                    provider: ProviderKind::Herdr,
                })
            }
        }
    }

    async fn resolve_tmux(&self, bridge_pid: u32) -> Option<AgentRouteProof> {
        let binary = self.workspace.resolve(ProviderKind::Tmux)?;
        let tty = process_tty(bridge_pid).await?;
        for pane in list_tmux_panes(&binary).await {
            if pane.pane_tty == tty && process::descends_from(bridge_pid, pane.pane_pid).await {
                return Some(AgentRouteProof::Tmux {
                    binary,
                    bridge_pid,
                    session_name: pane.session_name,
                    session_id: pane.session_id,
                    window_id: pane.window_id,
                    pane_id: pane.pane_id,
                    pane_pid: pane.pane_pid,
                    pane_tty: pane.pane_tty,
                });
            }
        }
        None
    }

    async fn resolve_herdr_workspace(&self, bridge_pid: u32) -> Option<AgentRouteProof> {
        let binary = self.workspace.resolve(ProviderKind::Herdr)?;
        let sessions = list_herdr_sessions(&binary).await;
        let mut inspected = 0_usize;
        for session_name in sessions {
            // One session's snapshot failing says nothing about the others: `session list`
            // includes stopped sessions, whose snapshot always fails, and a running one can time
            // out under load. This aborted the entire resolve, so whether a pane was found came
            // down to whether it sorted before the first failure — and a transient timeout on an
            // earlier session cost the route outright (measured 2026-08-19: the same pid and pane
            // resolved, failed, then resolved again across three daemon starts).
            let Some(snapshot) = herdr_snapshot(&binary, &session_name).await else {
                continue;
            };
            // Same reasoning as the snapshot above: an error envelope from one session is not a
            // verdict on the rest, and `?` here made it one.
            let Some(panes) = snapshot
                .get("result")
                .and_then(|value| value.get("snapshot"))
                .and_then(|value| value.get("panes"))
                .and_then(Value::as_array)
            else {
                continue;
            };
            for pane in panes {
                if inspected >= MAX_HERDR_PANES {
                    return None;
                }
                inspected += 1;
                // A pane missing either id is skipped, not fatal — an empty pane with no terminal
                // behind it is an ordinary thing to find, and abandoning the search at one cost
                // every pane after it.
                let (Some(pane_id), Some(terminal_id)) = (
                    pane.get("pane_id").and_then(Value::as_str),
                    pane.get("terminal_id").and_then(Value::as_str),
                ) else {
                    continue;
                };
                if !valid_provider_id(pane_id) || !valid_provider_id(terminal_id) {
                    continue;
                }
                // The same snapshot row names the tab, so the exact tab costs no extra call.
                // Continuity stays `WorkspaceOnly` regardless: focusing a tab is not the
                // non-displacing second-client guarantee that an exact-live claim would need.
                let tab_id = pane
                    .get("tab_id")
                    .and_then(|value| value.as_str())
                    .filter(|tab| valid_tab_id(tab))
                    .map(str::to_owned);
                if herdr_process_matches(&binary, &session_name, pane_id, terminal_id, bridge_pid)
                    .await
                {
                    return Some(AgentRouteProof::HerdrWorkspace {
                        binary,
                        bridge_pid,
                        session_name,
                        pane_id: pane_id.to_owned(),
                        terminal_id: terminal_id.to_owned(),
                        tab_id,
                    });
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TmuxPane {
    session_name: String,
    session_id: String,
    window_id: String,
    pane_id: String,
    pane_pid: u32,
    pane_tty: String,
}

async fn list_tmux_panes(binary: &Path) -> Vec<TmuxPane> {
    let Ok(output) = run_bounded(binary, &["list-panes", "-a", "-F", TMUX_ROUTE_FORMAT]).await
    else {
        return Vec::new();
    };
    if !output.status_success || output.stdout_truncated {
        return Vec::new();
    }
    parse_tmux_panes(&output.stdout)
}

fn parse_tmux_panes(stdout: &[u8]) -> Vec<TmuxPane> {
    let text = String::from_utf8_lossy(stdout);
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(UNIT_SEPARATOR).collect();
            let [
                session_name,
                session_id,
                window_id,
                pane_id,
                pane_pid,
                pane_tty,
            ] = <[&str; 6]>::try_from(fields).ok()?;
            if !valid_session_name(session_name)
                || !valid_tmux_id(session_id, '$')
                || !valid_tmux_id(window_id, '@')
                || !valid_tmux_id(pane_id, '%')
                || !valid_tty(pane_tty)
            {
                return None;
            }
            Some(TmuxPane {
                session_name: session_name.to_owned(),
                session_id: session_id.to_owned(),
                window_id: window_id.to_owned(),
                pane_id: pane_id.to_owned(),
                pane_pid: pane_pid.parse().ok().filter(|pid| *pid > 0)?,
                pane_tty: pane_tty.to_owned(),
            })
        })
        .collect()
}

fn valid_tmux_id(value: &str, prefix: char) -> bool {
    value.len() >= 2
        && value.len() <= MAX_OPAQUE_ID_BYTES
        && value.starts_with(prefix)
        && value[1..].bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_provider_id(value: &str) -> bool {
    valid_opaque_id(value).is_ok() || {
        !value.is_empty()
            && value.len() <= MAX_OPAQUE_ID_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-'))
    }
}

fn valid_tty(value: &str) -> bool {
    value.starts_with("/dev/tty")
        && value.len() <= MAX_OPAQUE_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
}

/// The controlling terminal of a process, refused unless it has the shape a route proof may
/// carry. `process::tty` reports what `ps` said; this is where that answer becomes admissible.
async fn process_tty(pid: u32) -> Option<String> {
    process::tty(pid).await.filter(|tty| valid_tty(tty))
}

/// Whether a registered agent process is the interactive TUI the user launched, rather than a
/// batch invocation of the same binary.
///
/// The test is per vendor because the giveaway is: Claude's is a flag, Codex's is a subcommand.
/// A shared list would let `codex exec` in CI register as an attached session on the strength of
/// Claude's flags not appearing in it.
pub(crate) async fn process_looks_like_tui(pid: u32, adapter: &str) -> bool {
    let Some(command) = process::command(pid).await else {
        return false;
    };
    let mut arguments = command.split_ascii_whitespace().skip(1);
    match adapter {
        // Codex's non-interactive modes are subcommands, and the first argument is where one
        // appears. Looking only there keeps a path or prompt containing the word "review" from
        // disqualifying a real TUI.
        "codex" => !arguments
            .next()
            .is_some_and(is_noninteractive_codex_subcommand),
        "claude" => !arguments.any(is_noninteractive_claude_argument),
        // A dialect this test has never met is refused, not handed Claude's heuristic: a
        // wrong "yes" here registers a batch process as an attached TUI.
        _ => false,
    }
}

fn is_noninteractive_codex_subcommand(argument: &str) -> bool {
    matches!(
        argument,
        "exec"
            | "e"
            | "app-server"
            | "mcp-server"
            | "exec-server"
            | "review"
            | "apply"
            | "a"
            | "cloud"
            | "debug"
            | "completion"
            | "doctor"
    )
}

fn is_noninteractive_claude_argument(argument: &str) -> bool {
    matches!(
        argument,
        "-p" | "--print"
            | "--input-format"
            | "--output-format"
            | "--json-schema"
            | "--init-only"
            | "--init"
            | "--maintenance"
    ) || (argument.starts_with("-p") && !argument.starts_with("--"))
        || [
            "--print=",
            "--input-format=",
            "--output-format=",
            "--json-schema=",
        ]
        .iter()
        .any(|prefix| argument.starts_with(prefix))
}

/// The process's start time, bounded by the opaque-identifier vocabulary a registration may
/// carry, because that is what this fingerprint has to travel inside.
pub(crate) async fn process_start_fingerprint(pid: u32) -> Option<String> {
    process::start_fingerprint(pid, MAX_OPAQUE_ID_BYTES).await
}

/// An agent herdr says is running, with the vendor session ID herdr read for it and the process
/// behind its pane: what a startup re-adoption needs to rebuild the registration the agent's own
/// hook would have sent. Raw and transient — the vendor ID is used for one keyed-digest lookup
/// and never stored (Spec 005 §8.2) — and a claim, not a proof: the caller accepts it only where
/// the persisted metadata already binds this exact process to that ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentSighting {
    pub(crate) vendor_session_id: String,
    pub(crate) process_id: u32,
    pub(crate) cwd: String,
}

impl TerminalRouteResolver {
    /// Every pane herdr says runs `adapter`, across its sessions, bounded like a route search.
    /// Each costs one `api snapshot` per session and one `pane process-info` per matching pane;
    /// any failure is simply no sighting.
    pub(crate) async fn herdr_agent_sightings(&self, adapter: &str) -> Vec<AgentSighting> {
        let Some(binary) = self.workspace.resolve(ProviderKind::Herdr) else {
            return Vec::new();
        };
        let mut sightings = Vec::new();
        let mut inspected = 0_usize;
        for session_name in list_herdr_sessions(&binary).await {
            let Some(snapshot) = herdr_snapshot(&binary, &session_name).await else {
                continue;
            };
            for (pane_id, vendor_session_id) in herdr_agent_panes(&snapshot, adapter) {
                if inspected >= MAX_HERDR_PANES {
                    return sightings;
                }
                inspected += 1;
                if let Some((process_id, cwd)) =
                    herdr_agent_process(&binary, &session_name, &pane_id, adapter).await
                {
                    sightings.push(AgentSighting {
                        vendor_session_id,
                        process_id,
                        cwd,
                    });
                }
            }
        }
        sightings
    }
}

/// The panes of one `api snapshot` whose agent herdr names `adapter` and identifies by session
/// ID (herdr 0.9.0: `agent_session: {agent, kind: "id", source, value}`). A pane naming this
/// agent whose identity is some other kind, or malformed, is the one input swallowed here — the
/// rest of a pane is deliberately ignored — so it is tallied for the drift ledger (Spec 017).
fn herdr_agent_panes(snapshot: &Value, adapter: &str) -> Vec<(String, String)> {
    let panes = snapshot
        .get("result")
        .and_then(|value| value.get("snapshot"))
        .and_then(|value| value.get("panes"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_HERDR_PANES);
    let mut found = Vec::new();
    for pane in panes {
        let Some(pane_id) = pane
            .get("pane_id")
            .and_then(Value::as_str)
            .filter(|id| valid_provider_id(id))
        else {
            continue;
        };
        let Some(session) = pane.get("agent_session") else {
            continue;
        };
        if session.get("agent").and_then(Value::as_str) != Some(adapter) {
            continue;
        }
        let identity = session
            .get("value")
            .and_then(Value::as_str)
            .filter(|_| session.get("kind").and_then(Value::as_str) == Some("id"))
            .filter(|id| valid_opaque_id(id).is_ok());
        match identity {
            Some(id) => found.push((pane_id.to_owned(), id.to_owned())),
            None => crate::drift::note("herdr", "agent_session", "invalid", "value", None),
        }
    }
    found
}

async fn herdr_agent_process(
    binary: &Path,
    session_name: &str,
    pane_id: &str,
    adapter: &str,
) -> Option<(u32, String)> {
    if !valid_session_name(session_name) || !valid_provider_id(pane_id) {
        return None;
    }
    let output = run_bounded(
        binary,
        &[
            "--session",
            session_name,
            "pane",
            "process-info",
            "--pane",
            pane_id,
        ],
    )
    .await
    .ok()?;
    if !output.status_success || output.stdout_truncated {
        return None;
    }
    let value = serde_json::from_slice::<Value>(&output.stdout).ok()?;
    parse_herdr_agent_process(&value, pane_id, adapter)
}

/// The pane's foreground process started as `adapter` (by `argv0`'s file name — Claude's binary
/// is named for its version, so the name is not it), with its absolute working directory.
fn parse_herdr_agent_process(value: &Value, pane_id: &str, adapter: &str) -> Option<(u32, String)> {
    let info = value.get("result")?.get("process_info")?;
    if info.get("pane_id").and_then(Value::as_str) != Some(pane_id) {
        return None;
    }
    info.get("foreground_processes")?
        .as_array()?
        .iter()
        .find_map(|process| {
            let argv0 = process.get("argv0")?.as_str()?;
            if Path::new(argv0).file_name()?.to_str()? != adapter {
                return None;
            }
            let pid = u32::try_from(process.get("pid")?.as_u64()?)
                .ok()
                .filter(|pid| *pid != 0)?;
            let cwd = process
                .get("cwd")?
                .as_str()
                .filter(|cwd| Path::new(cwd).is_absolute())?;
            Some((pid, cwd.to_owned()))
        })
}

async fn list_herdr_sessions(binary: &Path) -> Vec<String> {
    let Ok(output) = run_bounded(binary, &["session", "list", "--json"]).await else {
        return Vec::new();
    };
    if !output.status_success || output.stdout_truncated {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) else {
        return Vec::new();
    };
    value
        .get("sessions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("name").and_then(Value::as_str))
        .filter(|name| valid_session_name(name))
        .take(64)
        .map(str::to_owned)
        .collect()
}

async fn herdr_snapshot(binary: &Path, session_name: &str) -> Option<Value> {
    if !valid_session_name(session_name) {
        return None;
    }
    let output = run_bounded(binary, &["--session", session_name, "api", "snapshot"])
        .await
        .ok()?;
    if !output.status_success || output.stdout_truncated {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

async fn herdr_process_matches(
    binary: &Path,
    session_name: &str,
    pane_id: &str,
    terminal_id: &str,
    bridge_pid: u32,
) -> bool {
    if !valid_session_name(session_name)
        || !valid_provider_id(pane_id)
        || !valid_provider_id(terminal_id)
    {
        return false;
    }
    let Ok(output) = run_bounded(
        binary,
        &[
            "--session",
            session_name,
            "pane",
            "process-info",
            "--pane",
            pane_id,
        ],
    )
    .await
    else {
        return false;
    };
    if !output.status_success || output.stdout_truncated {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) else {
        return false;
    };
    let Some(info) = value
        .get("result")
        .and_then(|value| value.get("process_info"))
    else {
        return false;
    };
    if info.get("pane_id").and_then(Value::as_str) != Some(pane_id) {
        return false;
    }
    info.get("foreground_processes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|process| process.get("pid").and_then(Value::as_u64) == Some(u64::from(bridge_pid)))
}

#[cfg(test)]
pub(crate) fn validate_route_id(
    value: &str,
) -> Result<(), crate::agent_protocol::AgentProtocolError> {
    valid_opaque_id(value)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tempfile::tempdir;

    use super::*;

    fn executable(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A startup re-adoption reads two herdr documents: which panes name the agent by session
    /// ID, and which foreground process in that pane is the agent. The rest — a pane naming
    /// another agent, an identity of another kind, the shell beside the agent, a relative cwd,
    /// another pane's answer — names nothing.
    #[test]
    fn herdr_agent_sightings_parse_the_identity_and_the_process_behind_it() {
        let id = "0f8fad5b-d9cb-469f-a165-70867728950e";
        let snapshot = serde_json::json!({"result": {"snapshot": {"panes": [
            {"pane_id": "w1:p1", "agent_session":
                {"agent": "claude", "kind": "id", "source": "herdr:claude", "value": id}},
            {"pane_id": "w1:p2", "agent_session": {"agent": "codex", "kind": "id", "value": id}},
            {"pane_id": "w1:p3"},
            {"pane_id": "w1:p4", "agent_session": {"agent": "claude", "kind": "path", "value": id}},
            {"pane_id": "bad pane", "agent_session": {"agent": "claude", "kind": "id", "value": id}},
        ]}}});
        assert_eq!(
            herdr_agent_panes(&snapshot, "claude"),
            vec![("w1:p1".to_owned(), id.to_owned())]
        );

        let info = |pane: &str, cwd: &str, pid: u64| {
            serde_json::json!({"result": {"process_info": {"pane_id": pane, "foreground_processes": [
                {"argv0": "npm exec something", "pid": 11, "cwd": "/Users/u"},
                {"argv0": "claude", "argv": ["claude"], "name": "2.1.280", "pid": pid, "cwd": cwd},
            ]}}})
        };
        assert_eq!(
            parse_herdr_agent_process(&info("w1:p1", "/Users/u/project", 42), "w1:p1", "claude"),
            Some((42, "/Users/u/project".to_owned()))
        );
        assert_eq!(
            parse_herdr_agent_process(&info("w1:p9", "/Users/u/project", 42), "w1:p1", "claude"),
            None,
            "another pane's answer"
        );
        assert_eq!(
            parse_herdr_agent_process(&info("w1:p1", "project", 42), "w1:p1", "claude"),
            None
        );
        assert_eq!(
            parse_herdr_agent_process(&info("w1:p1", "/Users/u/project", 0), "w1:p1", "claude"),
            None
        );
    }

    #[test]
    fn tmux_proof_parser_uses_structured_ids_and_ignores_hostile_labels() {
        let valid = "safe_name\u{1f}$1\u{1f}@2\u{1f}%3\u{1f}42\u{1f}/dev/ttys001\n";
        let panes = parse_tmux_panes(valid.as_bytes());
        assert_eq!(panes.len(), 1);
        assert_eq!(panes[0].pane_id, "%3");

        for hostile in [
            "bad name\u{1f}$1\u{1f}@2\u{1f}%3\u{1f}42\u{1f}/dev/ttys001\n",
            "safe\u{1f}$(touch)\u{1f}@2\u{1f}%3\u{1f}42\u{1f}/dev/ttys001\n",
            "safe\u{1f}$1\u{1f}@2\u{1f}%3\u{1f}42\u{1f}/tmp/tty\n",
            "safe\u{1f}$1\u{1f}@2\u{1f}%3\u{1f}not-pid\u{1f}/dev/ttys001\n",
        ] {
            assert!(parse_tmux_panes(hostile.as_bytes()).is_empty());
        }
    }

    /// Both providers name the tab a different way, and the notification says the same word for
    /// both. The alternative — a proof carrying the label it was minted with — shows the tab's
    /// old name after a rename, which is exactly the fact the alert exists to get right.
    #[tokio::test]
    async fn a_tab_label_is_read_live_from_whichever_provider_owns_the_route() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("argv.log");

        let tmux = temp.path().join("tmux");
        executable(
            &tmux,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf 'website-redesign\\n'\nexit 0\n",
                log.display()
            ),
        );
        let resolver = TerminalRouteResolver::new(WorkspaceConfig::with_binary_dirs(vec![
            temp.path().to_owned(),
        ]));
        let window = AgentRouteProof::Tmux {
            session_name: "api".into(),
            binary: tmux,
            bridge_pid: std::process::id(),
            session_id: "$1".into(),
            window_id: "@2".into(),
            pane_id: "%3".into(),
            pane_pid: std::process::id(),
            pane_tty: "/dev/ttys001".into(),
        };
        assert_eq!(
            resolver.tab_label(&window).await.as_deref(),
            Some("website-redesign")
        );
        // The window id addresses the tab directly: no session name, no whole listing to join.
        let argv = fs::read_to_string(&log).unwrap();
        assert!(argv.contains("display-message -p -t @2"), "{argv}");

        let herdr = temp.path().join("herdr");
        executable(
            &herdr,
            "#!/bin/sh\nprintf '{\"result\":{\"tabs\":[{\"tab_id\":\"w9:t21\",\"label\":\"version-fixes\"},{\"tab_id\":\"w9:t2S\",\"label\":\"paste-image\"}]}}'\nexit 0\n",
        );
        let mut tab = AgentRouteProof::HerdrWorkspace {
            binary: herdr,
            bridge_pid: std::process::id(),
            session_name: "default".into(),
            pane_id: "w9:p2D".into(),
            terminal_id: "term_65b23b3c".into(),
            tab_id: Some("w9:t2S".into()),
        };
        assert_eq!(
            resolver.tab_label(&tab).await.as_deref(),
            Some("paste-image")
        );

        // An unnamed tab is reported by its id, which belongs in an argv and not on a lock
        // screen; the alert falls back to the workspace rather than showing `w9:t2S`.
        executable(
            &temp.path().join("herdr"),
            "#!/bin/sh\nprintf '{\"result\":{\"tabs\":[{\"tab_id\":\"w9:t2S\"}]}}'\nexit 0\n",
        );
        assert_eq!(resolver.tab_label(&tab).await, None);

        // A pane whose snapshot row named no tab leaves the alert unannotated rather than
        // guessing at the session's first one.
        if let AgentRouteProof::HerdrWorkspace { tab_id, .. } = &mut tab {
            *tab_id = None;
        }
        assert_eq!(resolver.tab_label(&tab).await, None);
    }

    #[tokio::test]
    async fn terminal_plan_uses_only_fixed_tmux_argv_and_rejects_stale_proof() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("argv.log");
        let tmux = temp.path().join("tmux");
        executable(
            &tmux,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$1\" in\nlist-panes) printf 'safe\\037$1\\037@2\\037%3\\037{}\\037/dev/ttys001\\n' ;;\nesac\nexit 0\n",
                log.display(),
                std::process::id()
            ),
        );
        let resolver = TerminalRouteResolver::new(WorkspaceConfig::with_binary_dirs(vec![
            temp.path().to_owned(),
        ]));
        let stale = AgentRouteProof::Tmux {
            session_name: "api".into(),
            binary: tmux,
            bridge_pid: std::process::id(),
            session_id: "$1".into(),
            window_id: "@2".into(),
            pane_id: "%3".into(),
            pane_pid: std::process::id(),
            pane_tty: "/dev/ttys001".into(),
        };
        // The current test process is not actually on the fabricated TTY, so revalidation fails
        // before either focus command can run.
        assert!(resolver.terminal_plan(&stale).await.is_none());
        let contents = fs::read_to_string(log).unwrap_or_default();
        assert!(!contents.contains("select-window"));
        assert!(!contents.contains("select-pane"));
    }

    #[tokio::test]
    async fn live_tmux_proof_requires_matching_tty_and_ancestry_and_uses_fixed_focus_argv() {
        let pid = std::process::id();
        let Some(tty) = process_tty(pid).await else {
            // The default Rust test harness often has no controlling TTY. Acceptance reruns this
            // focused test inside a disposable tmux PTY, where the full proof path is exercised.
            return;
        };
        let temp = tempdir().unwrap();
        let log = temp.path().join("argv.log");
        let tmux = temp.path().join("tmux");
        executable(
            &tmux,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$1\" in\n-V) printf 'tmux 3.6b\\n' ;;\nlist-panes) printf 'safe\\037$1\\037@2\\037%%3\\037{}\\037{}\\n' ;;\nesac\nexit 0\n",
                log.display(),
                pid,
                tty
            ),
        );
        let panes = list_tmux_panes(&tmux).await;
        assert_eq!(panes.len(), 1, "fake structured pane must parse");
        assert_eq!(panes[0].pane_tty, tty);
        assert_eq!(panes[0].pane_pid, pid);
        let resolver = TerminalRouteResolver::new(WorkspaceConfig::with_binary_dirs(vec![
            temp.path().to_owned(),
        ]));
        let proof = resolver.resolve(pid).await.expect("exact tmux proof");
        assert_eq!(proof.continuity(), RouteContinuity::ExactLive);
        let plan = resolver.terminal_plan(&proof).await.expect("fixed plan");
        assert_eq!(plan.provider, ProviderKind::Tmux);
        assert_eq!(
            plan.args,
            vec![
                OsString::from("attach-session"),
                OsString::from("-t"),
                OsString::from("$1")
            ]
        );
        let calls = fs::read_to_string(log).unwrap();
        assert!(calls.contains("select-window -t @2"));
        assert!(calls.contains("select-pane -t %3"));
        assert!(!calls.contains("safe"));
    }

    #[tokio::test]
    async fn grounded_system_tmux_proves_the_live_test_process_when_explicitly_enabled() {
        if std::env::var_os("CIAO_TEST_SYSTEM_TMUX").is_none() {
            return;
        }
        let directories = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let resolver = TerminalRouteResolver::new(WorkspaceConfig::with_binary_dirs(directories));
        let proof = resolver
            .resolve(std::process::id())
            .await
            .expect("running test process must correlate to its real tmux pane");
        assert_eq!(proof.continuity(), RouteContinuity::ExactLive);
        assert!(resolver.revalidate(&proof).await);
        let plan = resolver
            .terminal_plan(&proof)
            .await
            .expect("live focus plan");
        assert_eq!(plan.provider, ProviderKind::Tmux);
        assert_eq!(plan.args.first(), Some(&OsString::from("attach-session")));
    }

    #[test]
    fn claude_headless_arguments_are_rejected_conservatively() {
        for argument in [
            "-p",
            "-pSynthetic",
            "--print",
            "--output-format",
            "--output-format=stream-json",
            "--input-format",
            "--json-schema",
            "--init-only",
            "--maintenance",
        ] {
            assert!(is_noninteractive_claude_argument(argument));
        }
        for argument in [
            "--resume",
            "--continue",
            "--remote-control",
            "synthetic-prompt",
        ] {
            assert!(!is_noninteractive_claude_argument(argument));
        }
    }

    /// The `_` arm used to hand any future dialect Claude's argument heuristic, so a fifth
    /// adapter would have inherited a TUI test written for someone else's flags. Refusal is
    /// the conservative answer: a wrong "yes" registers a batch process as an attached TUI.
    #[tokio::test]
    async fn an_unknown_dialect_is_refused_rather_than_given_claudes_heuristic() {
        // This test's own process is real and carries no Claude headless flags, so the old
        // fallback would have said yes to it.
        assert!(!process_looks_like_tui(std::process::id(), "fixture").await);
    }

    #[test]
    fn route_identifiers_are_conservative_and_bounded() {
        assert!(validate_route_id(&"a".repeat(MAX_OPAQUE_ID_BYTES)).is_ok());
        assert!(validate_route_id(&"a".repeat(MAX_OPAQUE_ID_BYTES + 1)).is_err());
        assert!(validate_route_id("../route").is_err());
    }
}
