//! Merge-safe installation of Ciao's owned Codex hooks (Spec 012 §8, ARCHITECTURE §6.8).
//!
//! Unlike the Claude plugin, which owns a whole directory, this merges into a file the user and
//! third parties also write: `~/.codex/hooks.json` already carries herdr's `SessionStart` entry
//! on the grounded machine. Ciao owns only the entries whose command is its own, preserves every
//! other entry and its ordering, and never touches `config.toml`, `[hooks.state]`, or session
//! data.
//!
//! **The command string is frozen.** Codex takes its trust hash over that string alone — not
//! over what the command runs — so a byte-stable command keeps its trust across every Ciao
//! upgrade, while any variation re-gates all of Ciao's hooks behind an interactive review and
//! silently stops the live tail. `frozen_command_survives_an_upgrade` is the test that makes
//! changing it a deliberate act.

use std::{
    env, fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};

use crate::{
    agent_protocol::classify_vendor_version,
    codex_adapter::PINNED_CODEX_VERSION,
    codex_app_server,
    codex_hook::parse_codex_version_output,
    install::stable_binary_path,
    storage::{CiaoPaths, atomic_write_private},
};

const HOOKS_FILE_NAME: &str = "hooks.json";
const MAX_HOOKS_FILE_BYTES: u64 = 512 * 1024;
/// The hook argument. Frozen alongside the binary path; see the module note.
const HOOK_ARGUMENT: &str = "__codex-hook";
/// Seconds Codex waits for one hook. The delivery budget inside the hook is 1.5s, so this is
/// headroom for process start rather than a second budget.
const HOOK_TIMEOUT_SECONDS: u64 = 5;
/// `SessionEnd` is capped at 3s by Codex, and anything larger makes it print
/// "clamping SessionEnd hook timeout to 3s" into the user's TUI on every start. Ciao does not get
/// to add a warning to someone else's terminal. Verified safe: the trust hash covers the command
/// string, not the timeout, so this does not re-gate an installed hook.
const SESSION_END_TIMEOUT_SECONDS: u64 = 3;

/// Only the events the adapter actually maps. Installing a hook whose payload is dropped would
/// buy nothing and cost the user one more entry to approve.
const CIAO_EVENTS: [&str; 7] = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "Stop",
    "PermissionRequest",
    "SessionEnd",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexIntegrationStatus {
    NotInstalled,
    Installed,
    /// Installed, but Codex has not been told to trust the hooks yet, so none of them run.
    AwaitingTrust,
    UpdateAvailable,
    CodexUnavailable,
    /// Spec 017 §4.3: a later minor this machine has mechanically verified — every list the
    /// adapter reads is byte-identical to the pinned extract, so the grounding carried.
    CarriedVerified,
    UnsupportedCodexVersion,
}

impl CodexIntegrationStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotInstalled => "not installed",
            Self::Installed => "installed",
            Self::AwaitingTrust => {
                "installed; waiting to be approved in Codex — start `codex` and accept the new hooks"
            }
            Self::UpdateAvailable => "installed; update available",
            Self::CodexUnavailable => "installed; Codex is unavailable",
            Self::CarriedVerified => {
                "installed; current Codex version verified compatible on this machine (schema unchanged in everything Ciao reads)"
            }
            Self::UnsupportedCodexVersion => "installed; current Codex version is unsupported",
        }
    }
}

pub async fn install_codex_hooks(paths: &CiaoPaths) -> Result<CodexIntegrationStatus> {
    require_pinned_codex_version(paths).await?;
    let path = codex_hooks_path(paths);
    let command = ciao_hook_command(paths)?;
    let document = merge_ciao_hooks(read_existing(&path)?, &command)?;
    write_document(&path, &document)?;
    let written =
        read_existing(&path)?.ok_or_else(|| anyhow!("the written hooks file vanished"))?;
    if written != document {
        bail!("the written Codex hooks file did not match the validated content");
    }
    Ok(trust_status(paths, &command).await)
}

pub fn uninstall_codex_hooks(paths: &CiaoPaths) -> Result<bool> {
    let path = codex_hooks_path(paths);
    let Some(existing) = read_existing(&path)? else {
        return Ok(false);
    };
    let command = ciao_hook_command(paths)?;
    let pruned = remove_ciao_hooks(existing.clone(), &command);
    if pruned == existing {
        return Ok(false);
    }
    write_document(&path, &pruned)?;
    Ok(true)
}

pub async fn codex_integration_status(paths: &CiaoPaths) -> Result<CodexIntegrationStatus> {
    let path = codex_hooks_path(paths);
    let command = ciao_hook_command(paths)?;
    let Some(existing) = read_existing(&path)? else {
        return Ok(CodexIntegrationStatus::NotInstalled);
    };
    if !installed_events(&existing, &command)
        .iter()
        .all(|event| CIAO_EVENTS.contains(&event.as_str()))
        || installed_events(&existing, &command).len() != CIAO_EVENTS.len()
    {
        return Ok(if installed_events(&existing, &command).is_empty() {
            CodexIntegrationStatus::NotInstalled
        } else {
            CodexIntegrationStatus::UpdateAvailable
        });
    }
    Ok(match installed_codex_version(paths)? {
        None => CodexIntegrationStatus::CodexUnavailable,
        Some(version) if codex_version_supported(&version) => trust_status(paths, &command).await,
        // A carried version reads exactly like an installed one — trust still gates — and the
        // label says how it earned admission. Status never runs the verification itself;
        // install and setup do, and the daemon does at first contact.
        Some(version)
            if crate::codex_carry::state_for(
                &version,
                &paths.run_dir,
                codex_binary(paths).as_deref(),
            ) == crate::agent_protocol::VendorVersionState::Carried =>
        {
            match trust_status(paths, &command).await {
                CodexIntegrationStatus::Installed => CodexIntegrationStatus::CarriedVerified,
                other => other,
            }
        }
        Some(_) => CodexIntegrationStatus::UnsupportedCodexVersion,
    })
}

/// Asks Codex itself whether it will run Ciao's hooks. An untrusted hook does not fire, at user
/// scope as much as project scope, so an install that reports success without this reports a
/// live tail that does not exist.
///
/// Trust is the user's to grant: Ciao never writes `trusted_hash` into their config.
async fn trust_status(paths: &CiaoPaths, command: &str) -> CodexIntegrationStatus {
    let Some(binary) = codex_binary(paths) else {
        return CodexIntegrationStatus::Installed;
    };
    let Ok(result) = codex_app_server::request(&binary, "hooks/list", json!({})).await else {
        return CodexIntegrationStatus::Installed;
    };
    let mut seen = 0_usize;
    let mut trusted = 0_usize;
    for entry in result
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for hook in entry
            .get("hooks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if hook.get("command").and_then(Value::as_str) != Some(command) {
                continue;
            }
            seen += 1;
            if hook.get("trustStatus").and_then(Value::as_str) == Some("trusted") {
                trusted += 1;
            }
        }
    }
    if seen > 0 && trusted < seen {
        return CodexIntegrationStatus::AwaitingTrust;
    }
    CodexIntegrationStatus::Installed
}

fn codex_hooks_path(paths: &CiaoPaths) -> PathBuf {
    codex_home(paths).join(HOOKS_FILE_NAME)
}

pub(crate) fn codex_home(paths: &CiaoPaths) -> PathBuf {
    match env::var_os("CODEX_HOME") {
        Some(value) if !value.is_empty() && Path::new(&value).is_absolute() => PathBuf::from(value),
        _ => paths.home.join(".codex"),
    }
}

/// `'<binary>' __codex-hook`, quoted because Codex tokenizes the command string and a home
/// directory may contain spaces. A path containing a single quote is refused rather than
/// escaped: there is no escaping in the vendor's parser to be sure of.
fn ciao_hook_command(paths: &CiaoPaths) -> Result<String> {
    let binary = stable_binary_path(paths);
    let binary = binary
        .to_str()
        .ok_or_else(|| anyhow!("Ciao's stable binary path is not UTF-8"))?;
    if binary.contains('\'') || binary.contains('\n') {
        bail!("Ciao's stable binary path cannot be quoted for a Codex hook");
    }
    Ok(format!("'{binary}' {HOOK_ARGUMENT}"))
}

fn ciao_hook_entry(event: &str, command: &str) -> Value {
    json!({
        "type": "command",
        "command": command,
        "timeout": if event == "SessionEnd" {
            SESSION_END_TIMEOUT_SECONDS
        } else {
            HOOK_TIMEOUT_SECONDS
        }
    })
}

fn hook_group_is_ciao(group: &Value, command: &str) -> bool {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hooks| {
            hooks
                .iter()
                .any(|hook| hook.get("command").and_then(Value::as_str) == Some(command))
        })
}

/// Rewrites only Ciao's own entries, in place, preserving every other entry and its order.
fn merge_ciao_hooks(existing: Option<Value>, command: &str) -> Result<Value> {
    let mut document = match existing {
        Some(Value::Object(document)) => document,
        Some(_) => bail!("the Codex hooks file is not a JSON object"),
        None => Map::new(),
    };
    let mut hooks = match document.remove("hooks") {
        Some(Value::Object(hooks)) => hooks,
        Some(Value::Null) | None => Map::new(),
        Some(_) => bail!("the Codex hooks file has a `hooks` value that is not an object"),
    };
    for event in CIAO_EVENTS {
        let mut groups = match hooks.remove(event) {
            Some(Value::Array(groups)) => groups,
            Some(Value::Null) | None => Vec::new(),
            Some(_) => bail!("the Codex hooks file has an event that is not a list"),
        };
        groups.retain(|group| !hook_group_is_ciao(group, command));
        groups.push(json!({"hooks": [ciao_hook_entry(event, command)]}));
        hooks.insert(event.into(), Value::Array(groups));
    }
    document.insert("hooks".into(), Value::Object(hooks));
    Ok(Value::Object(document))
}

fn remove_ciao_hooks(existing: Value, command: &str) -> Value {
    let Value::Object(mut document) = existing else {
        return existing;
    };
    let Some(Value::Object(mut hooks)) = document.remove("hooks") else {
        return Value::Object(document);
    };
    let events: Vec<String> = hooks.keys().cloned().collect();
    for event in events {
        let Some(Value::Array(mut groups)) = hooks.remove(&event) else {
            continue;
        };
        groups.retain(|group| !hook_group_is_ciao(group, command));
        // An event left with no groups is removed rather than kept as an empty list, so an
        // uninstall leaves a file indistinguishable from one Ciao never touched.
        if !groups.is_empty() {
            hooks.insert(event, Value::Array(groups));
        }
    }
    document.insert("hooks".into(), Value::Object(hooks));
    Value::Object(document)
}

fn installed_events(existing: &Value, command: &str) -> Vec<String> {
    existing
        .get("hooks")
        .and_then(Value::as_object)
        .map(|hooks| {
            hooks
                .iter()
                .filter(|(_, groups)| {
                    groups.as_array().is_some_and(|groups| {
                        groups
                            .iter()
                            .any(|group| hook_group_is_ciao(group, command))
                    })
                })
                .map(|(event, _)| event.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn read_existing(path: &Path) -> Result<Option<Value>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect the Codex hooks file"),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.uid() != current_uid() {
        bail!("the Codex hooks file must be a same-user regular file");
    }
    if metadata.len() > MAX_HOOKS_FILE_BYTES {
        bail!("the Codex hooks file exceeded its byte bound");
    }
    let bytes = fs::read(path).context("read the Codex hooks file")?;
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        serde_json::from_slice(&bytes).context("parse the Codex hooks file")?,
    ))
}

fn write_document(path: &Path, document: &Value) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("the Codex hooks file has no parent directory"))?;
    ensure_owned_directory(parent)?;
    let mut encoded = serde_json::to_vec_pretty(document)?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_HOOKS_FILE_BYTES {
        bail!("the generated Codex hooks file exceeded its byte bound");
    }
    // Rolls back by construction: the temporary file is renamed over the target only after it
    // is completely written, so a failure leaves the user's own hooks untouched.
    atomic_write_private(path, &encoded).context("write the Codex hooks file")
}

fn ensure_owned_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir(path).context("create the Codex configuration directory")?;
    }
    let metadata = fs::symlink_metadata(path).context("inspect the Codex configuration")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != current_uid() {
        bail!("the Codex configuration must be a same-user regular directory");
    }
    Ok(())
}

/// The same rule `codex_hook.rs` runs at registration, applied where the install decides — the
/// two disagreed exactly as Claude's did, so a Codex that had auto-updated one patch was refused
/// hooks it would then have been served. Attached hooks are Codex's only surface, which makes a
/// wrong refusal here cost the whole integration rather than part of it.
pub(crate) fn codex_version_supported(version: &str) -> bool {
    // The shared classifier (Spec 017 §3). Identical outcome to the old tested-minor floor for
    // a 0.x pin — a later minor stays refused until Phase 3's schema extract can prove it —
    // but the rule now lives in one place for every gate.
    classify_vendor_version(version, PINNED_CODEX_VERSION).admitted()
}

pub(crate) async fn require_pinned_codex_version(paths: &CiaoPaths) -> Result<()> {
    match installed_codex_version(paths)? {
        Some(version) if codex_version_supported(&version) => Ok(()),
        // Spec 017 §4.3: `ciao setup` at first contact with a new Codex minor is exactly where
        // a person is waiting for a truthful answer, and the schema check costs well under a
        // second with zero model turns. Verified unchanged → admitted, and the verdict is
        // cached for the daemon and every hook.
        Some(version) => match crate::codex_carry::admit_interactively(paths, &version).await {
            Ok(true) => Ok(()),
            Ok(false) if crate::codex_carry::carry_eligible(&version) => bail!(
                "Codex {version} is installed and its schema changed in things Ciao reads, so this build cannot admit it. Run `ciao drift` for what moved; a Ciao release covers it."
            ),
            Ok(false) => bail!(
                "Codex {version} is installed, but this Ciao build supports {PINNED_CODEX_VERSION} and later releases of the same major that verify unchanged"
            ),
            Err(error) => bail!(
                "Codex {version} is installed but could not be verified ({error}); this build supports {PINNED_CODEX_VERSION} and later patches of that same minor"
            ),
        },
        None => bail!("Codex is not available on PATH"),
    }
}

pub(crate) fn installed_codex_version(paths: &CiaoPaths) -> Result<Option<String>> {
    let Some(binary) = codex_binary(paths) else {
        return Ok(None);
    };
    let output = match Command::new(&binary).arg("--version").output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect the Codex version"),
    };
    Ok(Some(parse_codex_version_output(&output)?))
}

/// `PATH` first, then the per-user location the npm install writes to — a daemon started by a
/// service manager frequently has neither the user's `PATH` nor a reason to care, and reporting
/// a correctly installed Codex as absent is a false negative in the first place anyone looks.
pub(crate) fn codex_binary(paths: &CiaoPaths) -> Option<PathBuf> {
    if Command::new("codex").arg("--version").output().is_ok() {
        return Some(PathBuf::from("codex"));
    }
    let candidate = paths.home.join(".local/bin/codex");
    let metadata = fs::metadata(&candidate).ok()?;
    (metadata.is_file() && metadata.uid() == current_uid()).then_some(candidate)
}

fn current_uid() -> u32 {
    nix::unistd::Uid::effective().as_raw()
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::agent_protocol::one_minor_past;

    const COMMAND: &str = "'/Users/synthetic/.local/bin/ciao' __codex-hook";

    #[test]
    fn the_codex_install_gate_covers_later_patches_and_still_refuses_a_minor_bump() {
        // Codex's install/status path was `==` while codex_hook.rs ran the range rule, the same
        // split Claude had. It costs more here: attached hooks are Codex's only surface, so a
        // wrong refusal loses the whole integration rather than the read-only half of it.
        assert!(codex_version_supported(PINNED_CODEX_VERSION));
        assert!(codex_version_supported("0.147.9"), "a later patch");
        assert!(!codex_version_supported("0.146.1"), "an older patch");
        // Computed, not spelled: the literal form of this case silently flips meaning at every
        // pin bump (vendor-version-policy trap #3). A 0.x minor stays refused until Phase 3
        // proves it mechanically.
        assert!(
            !codex_version_supported(&one_minor_past(PINNED_CODEX_VERSION)),
            "a minor bump of a 0.x pin"
        );
        assert!(!codex_version_supported("1.147.0"), "a major bump");
        assert!(!codex_version_supported("0.147.1-rc1"), "a prerelease");
        assert!(!codex_version_supported(""), "an unparseable version");
    }

    /// The exact shape `~/.codex/hooks.json` had on the grounded machine before Ciao touched it.
    fn herdr_document() -> Value {
        json!({
            "hooks": {
                "SessionStart": [{
                    "hooks": [{
                        "command": "bash '/Users/synthetic/.codex/herdr-agent-state.sh' session",
                        "timeout": 10,
                        "type": "command"
                    }]
                }]
            }
        })
    }

    #[test]
    fn a_merge_preserves_herdr_and_an_uninstall_gives_the_file_back() {
        let merged = merge_ciao_hooks(Some(herdr_document()), COMMAND).unwrap();
        let session_start = merged["hooks"]["SessionStart"].as_array().unwrap();
        assert_eq!(session_start.len(), 2);
        // Ordering matters: herdr binds its pane on the entry it already owns, and it stays
        // first because Ciao appends rather than rewriting the list.
        assert!(
            session_start[0]["hooks"][0]["command"]
                .as_str()
                .unwrap()
                .contains("herdr-agent-state.sh")
        );
        assert_eq!(session_start[1]["hooks"][0]["command"], json!(COMMAND));
        for event in CIAO_EVENTS {
            assert!(
                merged["hooks"][event].is_array(),
                "{event} was not installed"
            );
        }

        // Re-merging is idempotent: a second install does not stack duplicate entries.
        assert_eq!(
            merge_ciao_hooks(Some(merged.clone()), COMMAND).unwrap(),
            merged
        );

        let pruned = remove_ciao_hooks(merged, COMMAND);
        assert_eq!(pruned, herdr_document());
    }

    #[test]
    fn an_uninstall_never_removes_a_hook_ciao_does_not_own() {
        let foreign = json!({
            "hooks": {
                "Stop": [{"hooks": [{"type": "command", "command": "someone-elses-tool", "timeout": 3}]}]
            },
            "somethingElse": {"kept": true}
        });
        let merged = merge_ciao_hooks(Some(foreign.clone()), COMMAND).unwrap();
        assert_eq!(merged["somethingElse"], foreign["somethingElse"]);
        let pruned = remove_ciao_hooks(merged, COMMAND);
        assert_eq!(pruned, foreign);
    }

    /// Codex clamps a `SessionEnd` hook to 3s and prints a warning into the TUI when it has to.
    /// Ciao does not get to add noise to someone else's terminal, and the timeout is not part of
    /// the trust hash, so matching the cap costs nothing.
    #[test]
    fn session_end_uses_the_timeout_codex_will_not_clamp() {
        let document = merge_ciao_hooks(None, COMMAND).unwrap();
        assert_eq!(
            document["hooks"]["SessionEnd"][0]["hooks"][0]["timeout"],
            json!(3)
        );
        assert_eq!(
            document["hooks"]["UserPromptSubmit"][0]["hooks"][0]["timeout"],
            json!(5)
        );
    }

    #[test]
    fn a_fresh_install_writes_only_ciao_entries() {
        let document = merge_ciao_hooks(None, COMMAND).unwrap();
        let hooks = document["hooks"].as_object().unwrap();
        assert_eq!(hooks.len(), CIAO_EVENTS.len());
        // Events the adapter drops are not installed, so nobody is asked to approve a hook
        // whose payload Ciao throws away.
        for absent in ["PreCompact", "PostCompact", "SubagentStart", "SubagentStop"] {
            assert!(!hooks.contains_key(absent));
        }
    }

    #[test]
    fn frozen_command_survives_an_upgrade() {
        // Codex hashes the command string, so this shape is the trust key. Changing it — a new
        // argument, an unquoted path, a version in the command — re-gates every Ciao hook
        // behind an interactive review and silently stops the live tail on the machines that
        // already worked. Deleting this assertion is the only way to change it.
        let paths = CiaoPaths::for_home(Path::new("/Users/synthetic"));
        assert_eq!(
            ciao_hook_command(&paths).unwrap(),
            "'/Users/synthetic/.local/bin/ciao' __codex-hook"
        );
    }

    #[test]
    fn an_unquotable_binary_path_is_refused_rather_than_escaped() {
        let paths = CiaoPaths::for_home(Path::new("/Users/syn'thetic"));
        assert!(ciao_hook_command(&paths).is_err());
    }

    #[test]
    fn a_hostile_hooks_file_is_refused_rather_than_rewritten() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join(HOOKS_FILE_NAME);

        fs::write(&path, b"not json at all").unwrap();
        assert!(read_existing(&path).is_err());

        fs::write(&path, b"[1, 2, 3]").unwrap();
        let existing = read_existing(&path).unwrap();
        assert!(merge_ciao_hooks(existing, COMMAND).is_err());

        fs::write(&path, br#"{"hooks": {"Stop": "not a list"}}"#).unwrap();
        let existing = read_existing(&path).unwrap();
        assert!(merge_ciao_hooks(existing, COMMAND).is_err());

        std::os::unix::fs::symlink(
            temporary.path().join("elsewhere"),
            temporary.path().join("link"),
        )
        .unwrap();
        assert!(read_existing(&temporary.path().join("link")).is_err());
    }

    #[test]
    fn a_written_file_round_trips_through_the_reader() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join(HOOKS_FILE_NAME);
        let document = merge_ciao_hooks(Some(herdr_document()), COMMAND).unwrap();
        write_document(&path, &document).unwrap();
        assert_eq!(read_existing(&path).unwrap().unwrap(), document);
        assert_eq!(
            installed_events(&document, COMMAND).len(),
            CIAO_EVENTS.len()
        );
    }
}
