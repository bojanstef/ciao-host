//! What a phone may offer as slash commands for a terminal pane running Claude Code.
//!
//! The list is the vendor's own. Claude Code's commands are not a directory anyone can read:
//! about forty are compiled into the CLI, the rest come from skills, plugins, and per-project
//! files whose resolution rules belong to the CLI. Scraping `~/.claude/commands` returns
//! nothing at all on a machine that uses skills and plugins, which is the ordinary case. So
//! this asks the pinned SDK the same way the model picker asks for its catalogue: `supportedCommands()`
//! reports `{name, description, argumentHint, aliases}` for exactly the surface a Claude in that
//! directory would have.
//!
//! Three properties make it affordable, all measured against the pinned pair on 2026-08-20:
//! the call answers before any turn is streamed, so nothing is billed; it writes no session
//! file, so a picker that opens often leaves no litter; and it costs ~1.5 s, which is why the
//! answer is cached rather than fetched per keystroke.
//!
//! `settingSources` is the one place this deliberately differs from the managed worker. The
//! worker runs `[]` — documented Spec 006 isolation, so machine-local settings can never change
//! managed behavior. That is wrong here: this describes a *terminal* pane, where a real Claude
//! is running with the user's real settings, and `[]` reports 40 commands where the user has
//! 136. The isolation protects a session Ciao runs; this reads a session the user runs.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

use crate::{managed_worker::ManagedRuntime, workspace::read_capped};

/// The provider's word for a pane running Claude Code. Matched exactly: a dialect this build
/// has never met gets no picker rather than Claude's list.
pub(crate) const CLAUDE_AGENT: &str = "claude";

/// A ceiling for a wedged CLI, not a wait anyone is expected to sit through.
///
/// The probe answers in ~1.6 s. It took **17–21 s** inside the daemon until 2026-08-20, when the
/// LaunchAgent stopped declaring `ProcessType: Background` and stopped spawning every child into
/// PRIO_DARWIN_BG. That is fixed at the source now (`service.rs`), so this is generous rather
/// than load-bearing.
///
/// It deliberately stays at 45 s for one release anyway. `ciao update` runs the *old* CLI's
/// `install_launch_agent`, so an updating host writes the old `Background` plist and runs the
/// new daemon under it until the next setup — one release where the probe is still slow. A
/// shorter ceiling would turn that lag into a picker that never appears. Lower it once the
/// plist change has been through a release, and check
/// `IrohTransportActor.terminalSlashCommands`'s timeout in the same change: the app must always
/// wait longer than this, which is exactly the bug this had for most of 2026-08-20, with the
/// host answering at 18–20 s against a phone that gave up at 20 s.
const PROBE_TIMEOUT: Duration = Duration::from_secs(45);
const PROBE_STDOUT_CAP: usize = 256 * 1024;
/// Enough for a stack trace's first frames, which is all a log line can carry anyway.
const PROBE_STDERR_CAP: usize = 8 * 1024;

/// A cached list is stale the moment a skill file is written, and nothing here watches for
/// that. A minute is short enough that adding a command and reaching for it feels like it
/// worked, and long enough that opening the composer repeatedly costs one spawn.
const CACHE_TTL: Duration = Duration::from_secs(60);

/// Bounds on what may reach a phone. The owner's own machine reports 136 commands, so the
/// ceiling is set above the real world rather than at it, and an overshoot is truncated with a
/// drift note rather than refused whole.
pub(crate) const MAX_SLASH_COMMANDS: usize = 256;
pub(crate) const MAX_COMMAND_NAME_BYTES: usize = 64;
/// Per command. The vendor ships at most two today (`/usage` carries `/cost` and `/stats`); the
/// ceiling is above the real world rather than at it, and an overshoot is truncated.
pub(crate) const MAX_COMMAND_ALIASES: usize = 4;
pub(crate) const MAX_COMMAND_HINT_BYTES: usize = 64;
/// Vendor descriptions run past 400 bytes — they are model-facing prose, not row labels. A row
/// on a phone shows about this much, and the rest would be frame budget spent on text nobody
/// can read.
pub(crate) const MAX_COMMAND_DESCRIPTION_BYTES: usize = 96;

/// One offerable command, already bounded and safe to put on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlashCommand {
    /// Without the leading slash, exactly as the vendor spells it. `woz:woz-review` and
    /// `ios-feature-loop` are both ordinary.
    pub name: String,
    /// The vendor's argument hint (`<file>`, `[low|medium|high]`), or empty. Present because a
    /// command that takes arguments is the case where inserting-not-sending matters.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hint: String,
    /// Truncated vendor prose. Unlike the model catalogue — which drops descriptions because a
    /// model's display name says what it is — a list of ninety-four skills is unreadable
    /// without one: `example-discovery` and `example-tasks` name nothing on their own.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// The vendor's alternate names, which it ships and this used to discard.
    ///
    /// Measured on the owner's Mac 2026-08-20: **59 of 136 commands were reachable only by an
    /// alias**, so the picker could not find `/cost`, `/stats`, `/reset`, `/new`, `/settings`,
    /// `/review`, `/checkup`, or any unprefixed plugin shorthand — `/woz-review`, `/ponytail`,
    /// `/nextjs` — which is exactly how a person types them. Carried for matching, not as extra
    /// rows: one command stays one row, and picking it inserts the canonical name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Set for the hand-kept terminal-only commands, so a phone can mark them as belonging to
    /// the TUI rather than to the vendor's advertised surface. See `CLAUDE_TERMINAL_COMMANDS`.
    #[serde(default, skip_serializing_if = "is_not_set")]
    pub terminal: bool,
}

fn is_not_set(value: &bool) -> bool {
    !*value
}

/// Commands the CLI implements in its interactive layer and advertises **nowhere machine-readable**.
///
/// Established by measurement on 2026-08-20, against the pinned pair, in this order:
/// `supportedCommands()` omits them; the init message's `slash_commands` (139 entries) omits them
/// too, and its `terminal_slash_commands` tag covers only `doctor` and `color`; and the binary's
/// own command table is fragmented across a bundled runtime and mixes user-facing names with
/// `heapdump`, `mock-limits`, `reset-limits` and `simulate-usage`, with no marker separating
/// them. So this is hand-kept — the honest cost of offering `/exit` at all, which the owner asked
/// for by name.
///
/// Binary-confirmed present in 2.1.233: `add-dir`, `keybindings`, `output-style`,
/// `privacy-settings`, `release-notes`, `rewind`, `terminal-setup`. The rest are long-standing
/// and unconfirmed by that route.
///
/// **It defers to the vendor.** Any entry the live probe already advertises — as a name or as an
/// alias — is dropped at merge, so this shrinks by itself as the vendor's surface grows, and can
/// never shadow real data. A stale entry costs a rejected `/command` in the TUI, not a prompt:
/// the CLI refuses an unknown slash command rather than sending it to the model.
pub(crate) const CLAUDE_TERMINAL_COMMANDS: &[(&str, &str)] = &[
    ("exit", "Leave Claude Code and return to the shell"),
    ("help", "List the commands this Claude accepts"),
    ("resume", "Reopen an earlier conversation"),
    ("rewind", "Undo back to an earlier point"),
    ("export", "Write this conversation out to a file"),
    ("memory", "Edit the CLAUDE.md files in play"),
    ("add-dir", "Give Claude another directory to work in"),
    ("vim", "Toggle vim keys in the input"),
    ("login", "Sign in to your Anthropic account"),
    ("logout", "Sign out of your Anthropic account"),
    ("keybindings", "Change the key bindings"),
    ("output-style", "Change how Claude writes back"),
    ("terminal-setup", "Set up this terminal for Claude Code"),
    ("privacy-settings", "Review the privacy settings"),
    ("release-notes", "Show what changed in this version"),
];

/// The probe, as a module passed on the command line rather than a file installed next to the
/// worker. It needs no patching, no version of its own, and no place in
/// `ciao agent install claude` — which is the install step `worker.mjs` depends on and the
/// reason a host that skipped it runs a stale worker.
///
/// The prompt stream is a generator that never yields: `supportedCommands()` is a control
/// request, answered without a turn, and an input channel that stays open is what keeps the
/// query alive long enough to ask. Exiting explicitly is what stops the CLI outliving the answer.
const PROBE_SOURCE: &str = r#"
const { pathToFileURL } = await import("node:url");
const path = await import("node:path");
const sdk = await import(
  pathToFileURL(path.join(process.argv[1], "node_modules", "@anthropic-ai/claude-agent-sdk", "sdk.mjs")).href
);
const query = sdk.query({
  prompt: (async function* () { await new Promise(() => {}); })(),
  options: {
    cwd: process.argv[2],
    // The user's own settings, on purpose: this describes their terminal, not a managed session.
    settingSources: ["user", "project", "local"],
  },
});
const commands = await query.supportedCommands();
process.stdout.write(JSON.stringify({ commands }));
process.exit(0);
"#;

/// The same call with `settingSources: []`, which is the vendor's own way to say "built-in".
///
/// `[]` reports the ~40 commands compiled into the CLI; the user's sources report 136. The
/// difference *is* the skill-and-plugin surface, so the intersection identifies built-ins
/// authoritatively instead of by guessing at name shape — `clarify` and `clear` look identical
/// and only one of them is built in.
///
/// This exists because the vendor returns skills first. Measured 2026-08-20, of 136 rows:
/// `/doctor` was row 105, `/clear` 113, `/compact` 115, `/init` 121, `/model` 123, `/usage` 131.
/// A large installed skill set hid the built-in commands at the bottom of the picker.
///
/// Run concurrently with the main probe, so the second list costs no extra wall-clock.
const BUILTIN_PROBE_SOURCE: &str = r#"
const { pathToFileURL } = await import("node:url");
const path = await import("node:path");
const sdk = await import(
  pathToFileURL(path.join(process.argv[1], "node_modules", "@anthropic-ai/claude-agent-sdk", "sdk.mjs")).href
);
const query = sdk.query({
  prompt: (async function* () { await new Promise(() => {}); })(),
  options: { cwd: process.argv[2], settingSources: [] },
});
const commands = await query.supportedCommands();
process.stdout.write(JSON.stringify({ commands }));
process.exit(0);
"#;

#[derive(Debug, Deserialize)]
struct ProbeOutput {
    commands: Vec<ProbeCommand>,
}

#[derive(Debug, Deserialize)]
struct ProbeCommand {
    name: Option<String>,
    #[serde(rename = "argumentHint")]
    argument_hint: Option<String>,
    description: Option<String>,
    #[serde(default)]
    aliases: Option<Vec<String>>,
}

struct CacheEntry {
    cwd: PathBuf,
    fetched: Instant,
    commands: Vec<SlashCommand>,
}

/// ponytail: one entry, because a phone is looking at one terminal. Switching sessions costs
/// one re-probe. Make it a small map if two sessions are ever open at once.
static CACHE: Mutex<Option<CacheEntry>> = Mutex::new(None);

fn cached(cwd: &Path) -> Option<Vec<SlashCommand>> {
    let guard = CACHE.lock().ok()?;
    let entry = guard.as_ref()?;
    (entry.cwd == cwd && entry.fetched.elapsed() < CACHE_TTL).then(|| entry.commands.clone())
}

fn store(cwd: &Path, commands: &[SlashCommand]) {
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some(CacheEntry {
            cwd: cwd.to_owned(),
            fetched: Instant::now(),
            commands: commands.to_vec(),
        });
    }
}

#[cfg(test)]
pub(crate) fn clear_cache() {
    if let Ok(mut guard) = CACHE.lock() {
        *guard = None;
    }
}

/// The commands a Claude Code in `cwd` would offer, or an empty list.
///
/// Empty is the answer for every failure: no managed runtime installed, a node that will not
/// start, a wedged CLI, an unparseable answer. A picker that does not appear is a missing
/// affordance the user can work around by typing the command; a picker built from a guess is
/// wrong text sent to an agent.
pub(crate) async fn commands_for(
    sdk_prefix: &Path,
    worker_entrypoint: &Path,
    cwd: &Path,
) -> Vec<SlashCommand> {
    if let Some(hit) = cached(cwd) {
        return hit;
    }
    // Resolving the runtime is also the digest gate: the same verified pinned pair the managed
    // worker is allowed to spawn, never an unverified binary that happens to be on disk.
    let Ok(runtime) = ManagedRuntime::resolve(sdk_prefix, worker_entrypoint) else {
        return Vec::new();
    };
    // Concurrent, so identifying the built-ins costs no wall-clock over fetching the list.
    let (commands, builtins) = tokio::join!(
        probe(&runtime, cwd, PROBE_SOURCE),
        probe(&runtime, cwd, BUILTIN_PROBE_SOURCE)
    );
    let commands = arrange(commands, &builtins);
    // Cached even when empty. A machine without the runtime would otherwise spawn nothing but
    // pay the resolve on every compose-open, and a wedged CLI would be re-awaited every time.
    store(cwd, &commands);
    commands
}

/// Puts the commands a person is looking for where they can see them.
///
/// Three bands, in order: the terminal-only commands, then the CLI's built-ins, then everything
/// the user's own skills and plugins contribute — each band keeping the vendor's ordering inside
/// it. The vendor returns skills first, which put `/clear` at row 113 and `/model` at 123 of 136
/// and read to the owner as "there are no system commands".
///
/// This is also what makes the frame trim safe. `encode_terminal_commands_response_bounded`
/// sheds from the end, and before this the end was where every built-in lived — so the first
/// thing a too-large frame gave up was the description on `/compact`.
///
/// An empty `builtins` (the second probe failed) collapses to two bands rather than none: a
/// degraded order is still better than the vendor's, which buries them.
fn arrange(commands: Vec<SlashCommand>, builtins: &[SlashCommand]) -> Vec<SlashCommand> {
    let builtin_names: std::collections::HashSet<&str> =
        builtins.iter().map(|entry| entry.name.as_str()).collect();
    // Every name the vendor already answers to, alias included. The curated list defers to it.
    let advertised: std::collections::HashSet<&str> = commands
        .iter()
        .flat_map(|entry| {
            std::iter::once(entry.name.as_str())
                .chain(entry.aliases.iter().map(|alias| alias.as_str()))
        })
        .collect();

    let mut arranged: Vec<SlashCommand> = CLAUDE_TERMINAL_COMMANDS
        .iter()
        .filter(|(name, _)| !advertised.contains(name))
        .map(|(name, description)| SlashCommand {
            name: (*name).into(),
            hint: String::new(),
            description: clip((*description).into(), MAX_COMMAND_DESCRIPTION_BYTES),
            aliases: Vec::new(),
            terminal: true,
        })
        .collect();
    let (built_in, contributed): (Vec<_>, Vec<_>) = commands
        .into_iter()
        .partition(|entry| builtin_names.contains(entry.name.as_str()));
    arranged.extend(built_in);
    arranged.extend(contributed);
    arranged.truncate(MAX_SLASH_COMMANDS);
    arranged
}

/// Spawned plainly, at whatever priority the daemon runs at.
///
/// This used to wrap the spawn in `taskpolicy -c utility` to escape the background QoS the
/// daemon's `ProcessType: Background` imposed on every child. That was deployed and measured and
/// it did not work: `-c` is a *clamp*, which can only lower a QoS, so it could never raise
/// anything. Under the daemon's real posture the wrapper measured 29.2 s against 37.7 s
/// unwrapped — an extra process for nothing. `taskpolicy -B` on the spawned pid does not help
/// either; it returns success and leaves the process at PRI 4, because inherited
/// PRIO_DARWIN_BG is not something a child can shed.
///
/// The fix was one word in the LaunchAgent, where the priority is actually decided — see the
/// comment on `ProcessType` in `service.rs`. The probe needs no help once its parent is
/// `Standard`.
async fn probe(runtime: &ManagedRuntime, cwd: &Path, source: &str) -> Vec<SlashCommand> {
    let mut command = Command::new(&runtime.node_path);
    command
        .arg("--input-type=module")
        .arg("-e")
        .arg(source)
        // argv[1] and argv[2]: passed as arguments rather than interpolated into the source, so
        // no path can ever be read as script.
        .arg(&runtime.sdk_prefix)
        .arg(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Captured rather than discarded. A probe that fails silently is a picker that never
        // appears for a reason nobody can name — and on 2026-08-20 that cost an afternoon,
        // because every environment the failure was reproduced in from a shell worked fine and
        // the one that mattered had thrown its diagnostic away.
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear()
        .env("PATH", &runtime.tool_path)
        .env("HOME", home_directory())
        // The CLI self-updates by rewriting its own binary, which would invalidate the digest
        // the resolve above just checked. Same reason the managed worker sets it.
        .env("DISABLE_AUTOUPDATER", "1");

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            tracing::warn!(%error, "slash commands: the probe would not start");
            crate::drift::note("claude", "slash_commands", "probe", "spawn_failed", None);
            return Vec::new();
        }
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return Vec::new();
    };

    // Drained by its own task into a shared buffer rather than alongside stdout inside the
    // timeout. A timeout drops whatever it was awaiting, so stderr read that way is lost in
    // exactly the case that needs it — and a hang is the case that needs it most. Accumulating
    // as it arrives means the bytes survive the drop, and the child dying on drop is what
    // finally closes this pipe.
    let collected: Arc<Mutex<Vec<u8>>> = Arc::default();
    let sink = collected.clone();
    let draining = tokio::spawn(async move {
        let mut reader = stderr;
        let mut chunk = [0_u8; 4096];
        loop {
            match reader.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    let Ok(mut guard) = sink.lock() else { break };
                    let room = PROBE_STDERR_CAP.saturating_sub(guard.len());
                    if room == 0 {
                        break;
                    }
                    guard.extend_from_slice(&chunk[..count.min(room)]);
                }
            }
        }
    });

    // Deliberately only the answer, never the exit status.
    //
    // This used to `child.wait()` after reading stdout, and the daemon timed out here on
    // 2026-08-20 while every reproduction outside it answered in under five seconds: a shell,
    // a cleared environment, `/` as the working directory, reading to EOF, and a job submitted
    // to launchd's own user domain. The environment was ruled out; the await was not.
    //
    // Waiting is dropped rather than diagnosed further because it was never load-bearing. The
    // probe's whole contract is to print one JSON document: a document that parses *is* the
    // answer, and one that does not is a failure whatever the status says. Requiring a clean
    // exit only added a second way to block. `kill_on_drop` still collects the process.
    //
    // **Unproven:** what made `wait()` block. A wildcard `waitpid` elsewhere in the daemon
    // would do it by stealing the exit status, but `portable-pty` was checked and waits on its
    // own pids, so that is a suspect and not a finding. If this reappears, instrument the wait
    // itself rather than trusting this note.
    let read = timeout(PROBE_TIMEOUT, read_capped(stdout, PROBE_STDOUT_CAP)).await;

    match read {
        Ok((stdout, false)) => {
            draining.abort();
            normalize(&stdout)
        }
        // A truncated answer is a partial one, and half a JSON document parses as nothing
        // anyway. Named separately so the tally distinguishes it from a crash.
        Ok((_, true)) => {
            draining.abort();
            crate::drift::note("claude", "slash_commands", "probe", "truncated", None);
            Vec::new()
        }
        Err(_) => {
            let detail = drained(draining, &collected).await;
            tracing::warn!(
                seconds = PROBE_TIMEOUT.as_secs(),
                detail = %detail,
                "slash commands: the probe never answered"
            );
            crate::drift::note("claude", "slash_commands", "probe", "timed_out", None);
            Vec::new()
        }
    }
}

/// Whatever the probe managed to say, however it ended.
///
/// Resolved to a `String` before it reaches a `tracing` macro on purpose: awaiting inside macro
/// arguments makes the whole future non-`Send`, and this one is spawned per connection.
async fn drained(handle: tokio::task::JoinHandle<()>, collected: &Mutex<Vec<u8>>) -> String {
    // Bounded, so a pipe that never closes cannot hold the request open past its own timeout.
    let _ = timeout(Duration::from_secs(2), handle).await;
    collected
        .lock()
        .map(|guard| vendor_detail(&guard))
        .unwrap_or_else(|_| "unreadable".into())
}

/// A bounded, single-line excerpt of what the vendor said on stderr.
///
/// Diagnostic text only, and only into the local daemon log. Control bytes are stripped because
/// this lands in a log a person reads, and it is capped because a stack trace is not a message.
fn vendor_detail(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let flattened: String = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let trimmed = flattened.trim();
    if trimmed.is_empty() {
        return "no output".into();
    }
    trimmed.chars().take(400).collect()
}

/// The daemon runs under launchd with no `HOME`, and the CLI resolves the user's settings and
/// plugins under it. Falling back to the current directory rather than `/` keeps a missing
/// `HOME` from silently reading someone else's tree.
fn home_directory() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// Vendor input, tallied at its swallow point (Spec 017). A row that cannot be carried is
/// dropped by name rather than repaired: a truncated command *name* would be offered as a
/// command that does not exist, and tapping it would send text the agent cannot run.
pub(crate) fn normalize(stdout: &[u8]) -> Vec<SlashCommand> {
    let Ok(parsed) = serde_json::from_slice::<ProbeOutput>(stdout) else {
        crate::drift::note("claude", "slash_commands", "probe", "unparseable", None);
        return Vec::new();
    };

    let mut dropped = 0_u64;
    let mut commands: Vec<SlashCommand> = Vec::new();
    for entry in parsed.commands {
        let Some(name) = entry.name.filter(|name| valid_command_name(name)) else {
            dropped += 1;
            continue;
        };
        // An alias that fails the name rule is dropped rather than repaired, for the same reason
        // a bad name is: it would be offered as something typeable that does not exist. Losing
        // one alias still leaves the command findable under its own name.
        let aliases: Vec<String> = entry
            .aliases
            .unwrap_or_default()
            .into_iter()
            .filter(|alias| valid_command_name(alias) && alias.len() <= MAX_COMMAND_NAME_BYTES)
            .take(MAX_COMMAND_ALIASES)
            .collect();
        commands.push(SlashCommand {
            hint: clip(
                entry.argument_hint.unwrap_or_default(),
                MAX_COMMAND_HINT_BYTES,
            ),
            description: clip(
                entry.description.unwrap_or_default(),
                MAX_COMMAND_DESCRIPTION_BYTES,
            ),
            aliases,
            terminal: false,
            name,
        });
    }

    if dropped > 0 {
        // One weighted note rather than one per row: a vendor that changed the shape changed it
        // for every row, and N identical signatures say nothing N times.
        crate::drift::note_by(
            "claude",
            "slash_commands",
            "command",
            "unusable",
            None,
            dropped,
        );
    }
    if commands.len() > MAX_SLASH_COMMANDS {
        crate::drift::note_by(
            "claude",
            "slash_commands",
            "command",
            "over_bound",
            None,
            (commands.len() - MAX_SLASH_COMMANDS) as u64,
        );
        commands.truncate(MAX_SLASH_COMMANDS);
    }
    commands
}

/// The grammar a command name may wear on the wire. Deliberately wider than an identifier —
/// `woz:woz-review` and `cloudflare:build-mcp` are real — and deliberately narrower than
/// arbitrary text: this string is rendered as a row, prefixed with a slash, and typed into a
/// terminal, so whitespace and control bytes have no business in it.
fn valid_command_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_COMMAND_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

/// Truncates on a character boundary, never mid-codepoint. Hints and descriptions are display
/// text, so a clipped one is still useful; only names are dropped whole.
fn clip(mut value: String, cap: usize) -> String {
    if value.len() <= cap {
        return value;
    }
    let mut end = cap;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(commands: &str) -> Vec<u8> {
        format!("{{\"commands\":{commands}}}").into_bytes()
    }

    fn row(name: &str) -> SlashCommand {
        SlashCommand {
            name: name.into(),
            hint: String::new(),
            description: String::new(),
            aliases: Vec::new(),
            terminal: false,
        }
    }

    /// The defect the owner reported as "there's skills yes, but there's no system commands".
    ///
    /// They were there — at rows 105 to 136 of 136, because the vendor returns skills first. This
    /// asserts the three bands and, in particular, that a built-in outranks a skill whose name
    /// looks just like one: `clear` and `clarify` are indistinguishable by shape, which is why
    /// the second `settingSources: []` probe exists instead of a name heuristic.
    #[test]
    fn built_ins_and_terminal_commands_outrank_the_skills_that_used_to_bury_them() {
        let vendor = vec![
            row("clarify"),
            row("example-tasks"),
            row("woz:woz-review"),
            row("clear"),
            row("compact"),
        ];
        let builtins = vec![row("clear"), row("compact")];

        let arranged = arrange(vendor, &builtins);
        let names: Vec<&str> = arranged.iter().map(|entry| entry.name.as_str()).collect();

        let exit = names.iter().position(|name| *name == "exit").unwrap();
        let clear = names.iter().position(|name| *name == "clear").unwrap();
        let clarify = names.iter().position(|name| *name == "clarify").unwrap();
        assert!(exit < clear, "terminal commands lead: {names:?}");
        assert!(clear < clarify, "built-ins outrank skills: {names:?}");
        assert!(
            arranged[exit].terminal && !arranged[clear].terminal,
            "only the hand-kept rows are marked as terminal-only"
        );
        // Inside a band the vendor still decides, so `clear` stays ahead of `compact`.
        assert!(clear < names.iter().position(|name| *name == "compact").unwrap());

        // The curated list steps aside for anything the vendor already answers to, by name or
        // by alias — so it can never shadow real data and shrinks as the vendor grows.
        let mut advertised = row("usage");
        advertised.aliases = vec!["exit".into()];
        let deferred = arrange(vec![advertised], &[]);
        assert!(
            !deferred.iter().any(|entry| entry.name == "exit"),
            "an alias the vendor ships must suppress the hand-kept row: {deferred:?}"
        );

        // A failed second probe degrades to two bands rather than losing the ordering entirely.
        let degraded = arrange(vec![row("clarify"), row("clear")], &[]);
        assert_eq!(degraded.first().map(|entry| entry.terminal), Some(true));
    }

    /// The shape the pinned SDK actually returns, reduced to one row of each kind that matters:
    /// a plain built-in, a plugin-namespaced one, and one carrying an argument hint.
    #[test]
    fn a_real_answer_maps_to_bounded_rows() {
        let commands = normalize(&payload(
            r#"[
              {"name":"compact","description":"Summarize history","argumentHint":"<optional instructions>"},
              {"name":"woz:woz-review","description":"Deep multi-persona code review","argumentHint":""},
              {"name":"usage","description":"","argumentHint":"","aliases":["cost","stats"]}
            ]"#,
        ));
        assert_eq!(
            commands,
            vec![
                SlashCommand {
                    name: "compact".into(),
                    hint: "<optional instructions>".into(),
                    description: "Summarize history".into(),
                    aliases: Vec::new(),
                    terminal: false,
                },
                SlashCommand {
                    name: "woz:woz-review".into(),
                    hint: String::new(),
                    description: "Deep multi-persona code review".into(),
                    aliases: Vec::new(),
                    terminal: false,
                },
                SlashCommand {
                    name: "usage".into(),
                    hint: String::new(),
                    description: String::new(),
                    // Carried, not discarded. `/cost` and `/stats` are how a person reaches this
                    // row, and until 2026-08-20 dropping them made 59 of 136 commands
                    // unfindable by the name their user actually knows.
                    aliases: vec!["cost".into(), "stats".into()],
                    terminal: false,
                },
            ],
            "aliases are carried through; a key this build does not know is still ignored \
             rather than failing the parse"
        );
    }

    /// A name is an identifier: half of one names nothing, and offering it would send text the
    /// agent cannot run. Hints and descriptions are display text and survive clipped.
    #[test]
    fn a_name_that_cannot_be_carried_is_dropped_rather_than_repaired() {
        let long_name = "x".repeat(MAX_COMMAND_NAME_BYTES + 1);
        let commands = normalize(&payload(&format!(
            r#"[
              {{"name":"{long_name}","description":"over the name bound"}},
              {{"name":"has space","description":"whitespace is not a command name"}},
              {{"name":"","description":"empty"}},
              {{"description":"no name at all"}},
              {{"name":"kept","description":"{}","argumentHint":"{}"}}
            ]"#,
            "d".repeat(MAX_COMMAND_DESCRIPTION_BYTES + 40),
            "h".repeat(MAX_COMMAND_HINT_BYTES + 40),
        )));
        assert_eq!(commands.len(), 1, "only the carryable row survives");
        assert_eq!(commands[0].name, "kept");
        assert_eq!(commands[0].description.len(), MAX_COMMAND_DESCRIPTION_BYTES);
        assert_eq!(commands[0].hint.len(), MAX_COMMAND_HINT_BYTES);
    }

    /// Truncation never splits a codepoint, because the result is rendered.
    #[test]
    fn clipping_lands_on_a_character_boundary() {
        // Three-byte characters against a cap that falls inside the last one.
        let clipped = clip("★".repeat(40), MAX_COMMAND_DESCRIPTION_BYTES);
        assert!(clipped.len() <= MAX_COMMAND_DESCRIPTION_BYTES);
        assert_eq!(clipped.chars().count(), MAX_COMMAND_DESCRIPTION_BYTES / 3);
        assert!(std::str::from_utf8(clipped.as_bytes()).is_ok());
    }

    /// A vendor that starts answering with something else costs the picker, never the session.
    #[test]
    fn an_unreadable_answer_is_an_empty_list() {
        assert!(normalize(b"not json").is_empty());
        assert!(normalize(b"{}").is_empty(), "no `commands` key");
        assert!(normalize(&payload("\"a string\"")).is_empty());
        assert!(normalize(&payload("[]")).is_empty());
    }

    /// The published list is bounded even if the vendor's is not.
    #[test]
    fn an_over_long_catalogue_is_truncated_rather_than_refused() {
        let rows: Vec<String> = (0..MAX_SLASH_COMMANDS + 12)
            .map(|index| format!("{{\"name\":\"cmd{index}\"}}"))
            .collect();
        let commands = normalize(&payload(&format!("[{}]", rows.join(","))));
        assert_eq!(commands.len(), MAX_SLASH_COMMANDS);
        assert_eq!(commands[0].name, "cmd0", "the head is kept, not the tail");
    }

    /// The whole path against the real installed pair, on demand. Everything above this is
    /// mapping; this is the only thing that can say the spawn, the flags, the environment, and
    /// the SDK call still agree with each other.
    ///
    /// Off by default and never in CI: it needs a machine where `ciao agent install claude` has
    /// run, and it spawns the real CLI. It bills nothing — `supportedCommands()` is answered
    /// before a turn exists — which is what makes it safe to re-run whenever the pin moves.
    ///
    ///   CIAO_TEST_SLASH_PROBE=1 cargo test -p ciao-host --lib \
    ///     grounded_probe -- --nocapture --ignored
    ///
    /// Measured here on 2026-08-20, pinned pair 2.1.233/0.3.233, 138 commands: the probe itself
    /// is 1.63 s and the cache answers in ~30 µs. A first read in a fresh *process* also paid
    /// 14.08 s inside `ManagedRuntime::resolve`, which hashes the ~257 MB CLI; that is why the
    /// daemon warms the same verdict at startup (`warm_managed_runtime`) instead of leaving it
    /// on whoever asks first. This test does not assert the cold number, because it measures a
    /// digest that a warmed daemon has already paid and a fresh `cargo test` has not.
    /// ponytail: proving the bytes the phone actually receives are decodable, rather than
    /// reasoning about them. Dumps the real encoded frame so it can be checked against the app's
    /// own rules outside Rust.
    ///
    ///   CIAO_TEST_SLASH_PROBE=1 cargo test -p ciao-host --lib grounded_frame \
    ///     -- --nocapture --ignored
    #[tokio::test]
    #[ignore = "spawns the real pinned CLI; run by hand"]
    async fn grounded_frame_is_what_the_phone_will_actually_be_sent() {
        if std::env::var_os("CIAO_TEST_SLASH_PROBE").is_none() {
            eprintln!("skipped: set CIAO_TEST_SLASH_PROBE=1");
            return;
        }
        let paths = crate::storage::CiaoPaths::discover().expect("storage paths resolve");
        let cwd = std::env::current_dir().expect("a working directory");
        clear_cache();
        let commands = commands_for(
            &paths.managed_sdk_prefix,
            &paths.managed_worker_entrypoint,
            &cwd,
        )
        .await;
        let offered = commands.len();
        let response = crate::host_protocol::TerminalCommandsResponse::new(
            "AAECAwQFBgcICQoLDA0ODw".into(),
            commands,
        );
        let (encoded, bounded) =
            crate::host_protocol::encode_terminal_commands_response_bounded(response)
                .expect("the real frame must encode");
        bounded.validate().expect("the real frame must validate");
        // The 4-byte length prefix is not part of the body the app parses.
        let body = &encoded[4..];
        std::fs::write("/tmp/frame.json", body).expect("dump the frame");
        eprintln!(
            "offered={offered} sent={} bytes={} (cap {})",
            bounded.result.commands.len(),
            body.len(),
            crate::host_protocol::MAX_RPC_BODY
        );
    }

    #[tokio::test]
    #[ignore = "spawns the real pinned CLI; run by hand"]
    async fn grounded_probe_reads_the_live_command_surface_when_explicitly_enabled() {
        if std::env::var_os("CIAO_TEST_SLASH_PROBE").is_none() {
            eprintln!("skipped: set CIAO_TEST_SLASH_PROBE=1 to run against the installed pair");
            return;
        }
        let paths = crate::storage::CiaoPaths::discover().expect("storage paths resolve");
        let cwd = std::env::current_dir().expect("a working directory");

        clear_cache();
        let began = Instant::now();
        let commands = commands_for(
            &paths.managed_sdk_prefix,
            &paths.managed_worker_entrypoint,
            &cwd,
        )
        .await;
        let cold = began.elapsed();

        let began = Instant::now();
        let again = commands_for(
            &paths.managed_sdk_prefix,
            &paths.managed_worker_entrypoint,
            &cwd,
        )
        .await;
        let warm = began.elapsed();

        eprintln!(
            "commands={} cold={cold:?} warm={warm:?}\nfirst five: {:#?}",
            commands.len(),
            commands.iter().take(5).collect::<Vec<_>>()
        );
        assert!(
            !commands.is_empty(),
            "the installed pair reported no commands; \
             `ciao agent install claude` may not have run on this machine"
        );
        assert_eq!(again, commands, "the cache answers with the same list");
        assert!(
            warm < Duration::from_millis(50),
            "the second read must be the cache, not another spawn: {warm:?}"
        );
        assert!(
            commands.iter().any(|entry| entry.name == "compact"),
            "a built-in the CLI always carries is missing, so this is not the real surface"
        );
    }

    /// Names carry vendor namespacing and nothing that would misbehave typed into a terminal.
    #[test]
    fn the_name_grammar_admits_namespaces_and_refuses_control_bytes() {
        for good in [
            "compact",
            "woz:woz-review",
            "cloudflare:build-mcp",
            "ios_feature.loop",
            "usage-credits",
        ] {
            assert!(valid_command_name(good), "should be admitted: {good}");
        }
        for bad in [
            "",
            "with space",
            "new\nline",
            "semi;colon",
            "quote\"mark",
            "dollar$sign",
            "slash/inside",
            "back\\slash",
        ] {
            assert!(!valid_command_name(bad), "should be refused: {bad}");
        }
    }
}
