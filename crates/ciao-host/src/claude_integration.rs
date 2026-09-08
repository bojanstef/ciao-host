//! Merge-safe installation for Ciao's owned Claude Code command-hook plugin.
//!
//! Claude discovers personal plugins under its documented `~/.claude/skills` directory. Ciao
//! owns one complete plugin directory there and never edits Claude settings, project files,
//! marketplaces, permissions, credentials, or another plugin.

use std::{
    env, fs,
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::{
    agent_protocol::{VendorVersionState, classify_vendor_version},
    claude_adapter::PINNED_CLAUDE_VERSION,
    install::stable_binary_path,
    storage::{CiaoPaths, atomic_write_private, validate_private_file},
};

const PLUGIN_DIRECTORY_NAME: &str = "ciao-agent-session";
const MANIFEST_DIRECTORY_NAME: &str = ".claude-plugin";
const MANIFEST_FILE_NAME: &str = "plugin.json";
const HOOKS_DIRECTORY_NAME: &str = "hooks";
const HOOKS_FILE_NAME: &str = "hooks.json";
const OWNERSHIP_MARKER: &str = "Ciao attached Agent Session hooks";
const MAX_PLUGIN_FILE_BYTES: u64 = 128 * 1024;
const MAX_VERSION_OUTPUT_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeIntegrationStatus {
    NotInstalled,
    Installed,
    UpdateAvailable,
    ClaudeUnavailable,
    /// Spec 017 §3: a later 2.x minor — admitted, observed in full, drift tallied. The label
    /// says so plainly instead of pretending either full grounding or unsupportedness.
    AheadOfTested,
    UnsupportedClaudeVersion,
}

impl ClaudeIntegrationStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotInstalled => "not installed",
            Self::Installed => "installed",
            Self::UpdateAvailable => "installed; update available",
            Self::ClaudeUnavailable => "installed; Claude Code is unavailable",
            Self::AheadOfTested => {
                "installed; Claude Code is newer than this Ciao was tested with (watching works, run `ciao drift` for anything unrecognized)"
            }
            Self::UnsupportedClaudeVersion => {
                "installed; current Claude Code version is unsupported"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PluginFiles {
    manifest: Vec<u8>,
    hooks: Vec<u8>,
}

pub fn install_claude_plugin(paths: &CiaoPaths) -> Result<ClaudeIntegrationStatus> {
    require_pinned_claude_version(paths)?;
    let target = claude_plugin_path(paths)?;
    install_at(&target, &expected_plugin(paths)?)
}

/// Re-installs an already-installed plugin whose content predates this binary, and does nothing
/// otherwise. The hook set ships inside the daemon, so an upgraded host that keeps yesterday's
/// `hooks.json` keeps observing yesterday's events — silently, on exactly the machines that
/// already work. Opt-in is still the user's: a host that never installed stays uninstalled.
///
/// Unlike opting in, this does not require the pinned Claude Code on `PATH`: a daemon started by
/// a service manager frequently has neither the user's `PATH` nor a reason to care, and the file
/// it writes is Ciao's own. An unsupported Claude Code is still refused where it matters — the
/// hook command checks the running version itself and reports nothing but a heartbeat.
pub fn refresh_installed_claude_plugin(paths: &CiaoPaths) -> Result<bool> {
    refresh_at(&claude_plugin_path(paths)?, &expected_plugin(paths)?)
}

fn refresh_at(target: &Path, expected: &PluginFiles) -> Result<bool> {
    let Some(existing) = read_existing_owned(target)? else {
        return Ok(false);
    };
    if &existing == expected {
        return Ok(false);
    }
    install_at(target, expected)?;
    Ok(true)
}

pub fn uninstall_claude_plugin(paths: &CiaoPaths) -> Result<bool> {
    uninstall_at(&claude_plugin_path(paths)?)
}

pub fn claude_integration_status(paths: &CiaoPaths) -> Result<ClaudeIntegrationStatus> {
    let target = claude_plugin_path(paths)?;
    let expected = expected_plugin(paths)?;
    let Some(existing) = read_existing_owned(&target)? else {
        return Ok(ClaudeIntegrationStatus::NotInstalled);
    };
    if existing != expected {
        return Ok(ClaudeIntegrationStatus::UpdateAvailable);
    }
    validate_installed(&target, &expected)?;
    Ok(match installed_claude_version(paths)? {
        None => ClaudeIntegrationStatus::ClaudeUnavailable,
        Some(version) => match claude_version_state(&version) {
            // Claude has no prover, so `Carried` is unreachable here; mapping it like
            // grounded keeps the match honest if one ever exists.
            VendorVersionState::Grounded | VendorVersionState::Carried => {
                ClaudeIntegrationStatus::Installed
            }
            VendorVersionState::Ahead => ClaudeIntegrationStatus::AheadOfTested,
            VendorVersionState::Unsupported => ClaudeIntegrationStatus::UnsupportedClaudeVersion,
        },
    })
}

fn claude_plugin_path(paths: &CiaoPaths) -> Result<PathBuf> {
    let config = match env::var_os("CLAUDE_CONFIG_DIR") {
        Some(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                bail!("CLAUDE_CONFIG_DIR must be an absolute path");
            }
            path
        }
        _ => paths.home.join(".claude"),
    };
    Ok(config.join("skills").join(PLUGIN_DIRECTORY_NAME))
}

fn expected_plugin(paths: &CiaoPaths) -> Result<PluginFiles> {
    let binary_path = stable_binary_path(paths);
    let binary = binary_path
        .to_str()
        .ok_or_else(|| anyhow!("Ciao's stable binary path is not UTF-8"))?;
    let manifest = json!({
        "name": PLUGIN_DIRECTORY_NAME,
        "displayName": "Ciao Agent Sessions",
        "version": env!("CARGO_PKG_VERSION"),
        "description": OWNERSHIP_MARKER,
        "author": { "name": "Ciao" },
        "license": "MIT OR Apache-2.0"
    });
    let command_hook = json!({
        "type": "command",
        "command": binary,
        "args": ["__claude-hook"],
        "timeout": 2
    });
    let event_hooks = |matcher: Option<&str>| {
        let mut group = serde_json::Map::new();
        if let Some(matcher) = matcher {
            group.insert("matcher".into(), Value::String(matcher.into()));
        }
        group.insert("hooks".into(), Value::Array(vec![command_hook.clone()]));
        Value::Object(group)
    };
    let hooks = json!({
        "description": OWNERSHIP_MARKER,
        "hooks": {
            "SessionStart": [event_hooks(None)],
            "UserPromptSubmit": [event_hooks(None)],
            "MessageDisplay": [event_hooks(None)],
            // The turn-close edge (Spec 019). Subscribed since 2026-08-17: the mapper had an arm
            // for it from the first commit, this list never did, so every attached turn opened
            // and none closed. Its payload repeats the opening `prompt_id`, which is how a close
            // names the run it closes.
            "Stop": [event_hooks(None)],
            // The "needs you" signal: Claude Code raises this for a permission prompt and for
            // an idle prompt, and it is the only hook that reports either (ADR 005).
            "Notification": [event_hooks(None)],
            "PreToolUse": [event_hooks(None)],
            "PostToolUse": [event_hooks(None)],
            "PostToolUseFailure": [event_hooks(None)],
            "StopFailure": [event_hooks(None)],
            "PreCompact": [event_hooks(None)],
            "PostCompact": [event_hooks(None)],
            "SessionEnd": [event_hooks(None)]
        }
    });
    Ok(PluginFiles {
        manifest: serde_json::to_vec_pretty(&manifest)?,
        hooks: serde_json::to_vec_pretty(&hooks)?,
    })
}

fn install_at(target: &Path, expected: &PluginFiles) -> Result<ClaudeIntegrationStatus> {
    validate_expected(expected)?;
    let skills = target
        .parent()
        .ok_or_else(|| anyhow!("Claude plugin target has no parent"))?;
    let claude = skills
        .parent()
        .ok_or_else(|| anyhow!("Claude skills target has no parent"))?;
    ensure_owned_directory(claude, "Claude configuration")?;
    ensure_owned_directory(skills, "Claude skills")?;

    let previous = read_existing_owned(target)?;
    if previous.as_ref() == Some(expected) {
        secure_plugin_tree(target)?;
        validate_installed(target, expected)?;
        return Ok(ClaudeIntegrationStatus::Installed);
    }

    let suffix = std::process::id();
    let staging = skills.join(format!(".{PLUGIN_DIRECTORY_NAME}.stage.{suffix}"));
    let backup = skills.join(format!(".{PLUGIN_DIRECTORY_NAME}.backup.{suffix}"));
    remove_stale_owned_tree(&staging)?;
    remove_stale_owned_tree(&backup)?;
    write_plugin_tree(&staging, expected)?;
    validate_installed(&staging, expected)?;

    let had_previous = previous.is_some();
    if had_previous {
        fs::rename(target, &backup).context("back up the previous Ciao Claude plugin")?;
    }
    let install_result = fs::rename(&staging, target)
        .context("activate the Ciao Claude plugin")
        .and_then(|()| validate_installed(target, expected));
    if let Err(error) = install_result {
        let _ = remove_owned_tree(target);
        if had_previous && backup.exists() {
            let _ = fs::rename(&backup, target);
        }
        let _ = remove_owned_tree(&staging);
        return Err(error.context("Ciao Claude plugin installation was rolled back"));
    }
    if backup.exists() {
        remove_owned_tree(&backup).context("remove Ciao Claude plugin backup")?;
    }
    File::open(skills)?.sync_all()?;
    Ok(ClaudeIntegrationStatus::Installed)
}

fn uninstall_at(target: &Path) -> Result<bool> {
    let Some(_) = read_existing_owned(target)? else {
        return Ok(false);
    };
    let parent = target
        .parent()
        .ok_or_else(|| anyhow!("Claude plugin target has no parent"))?;
    remove_owned_tree(target).context("remove the Ciao Claude plugin")?;
    File::open(parent)?.sync_all()?;
    Ok(true)
}

fn write_plugin_tree(target: &Path, files: &PluginFiles) -> Result<()> {
    fs::create_dir(target).context("create staged Ciao Claude plugin")?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o700))?;
    let manifest_dir = target.join(MANIFEST_DIRECTORY_NAME);
    let hooks_dir = target.join(HOOKS_DIRECTORY_NAME);
    fs::create_dir(&manifest_dir)?;
    fs::create_dir(&hooks_dir)?;
    fs::set_permissions(&manifest_dir, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&hooks_dir, fs::Permissions::from_mode(0o700))?;
    atomic_write_private(&manifest_dir.join(MANIFEST_FILE_NAME), &files.manifest)?;
    atomic_write_private(&hooks_dir.join(HOOKS_FILE_NAME), &files.hooks)?;
    File::open(&manifest_dir)?.sync_all()?;
    File::open(&hooks_dir)?.sync_all()?;
    File::open(target)?.sync_all()?;
    Ok(())
}

fn read_existing_owned(target: &Path) -> Result<Option<PluginFiles>> {
    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect Ciao Claude plugin"),
    };
    validate_directory_metadata(&metadata, "Ciao Claude plugin")?;
    require_exact_entries(target, &[MANIFEST_DIRECTORY_NAME, HOOKS_DIRECTORY_NAME])?;
    let manifest_dir = target.join(MANIFEST_DIRECTORY_NAME);
    let hooks_dir = target.join(HOOKS_DIRECTORY_NAME);
    validate_owned_directory(&manifest_dir, "Ciao Claude manifest directory")?;
    validate_owned_directory(&hooks_dir, "Ciao Claude hooks directory")?;
    require_exact_entries(&manifest_dir, &[MANIFEST_FILE_NAME])?;
    require_exact_entries(&hooks_dir, &[HOOKS_FILE_NAME])?;
    let manifest = read_owned_file(&manifest_dir.join(MANIFEST_FILE_NAME))?;
    let hooks = read_owned_file(&hooks_dir.join(HOOKS_FILE_NAME))?;
    if !contains_marker(&manifest) || !contains_marker(&hooks) {
        bail!("the Ciao Claude plugin directory is occupied by different content");
    }
    Ok(Some(PluginFiles { manifest, hooks }))
}

fn read_owned_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).context("inspect Ciao Claude plugin file")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.uid() != current_uid() {
        bail!("Ciao Claude plugin file is unsafe");
    }
    if metadata.len() == 0 || metadata.len() > MAX_PLUGIN_FILE_BYTES {
        bail!("Ciao Claude plugin file is unrecognized");
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    File::open(path)?
        .take(MAX_PLUGIN_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PLUGIN_FILE_BYTES {
        bail!("Ciao Claude plugin file exceeded its bound");
    }
    Ok(bytes)
}

fn contains_marker(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|value| value.contains(OWNERSHIP_MARKER))
}

fn require_exact_entries(directory: &Path, expected: &[&str]) -> Result<()> {
    let mut actual = Vec::new();
    for entry in fs::read_dir(directory).context("list Ciao Claude plugin directory")? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("Ciao Claude plugin contains a non-UTF-8 entry"))?;
        actual.push(name);
    }
    actual.sort();
    let mut expected: Vec<_> = expected.iter().map(|value| (*value).to_owned()).collect();
    expected.sort();
    if actual != expected {
        bail!("Ciao Claude plugin contains unrecognized entries");
    }
    Ok(())
}

fn validate_installed(target: &Path, expected: &PluginFiles) -> Result<()> {
    let actual = read_existing_owned(target)?
        .ok_or_else(|| anyhow!("installed Ciao Claude plugin disappeared"))?;
    if &actual != expected {
        bail!("installed Ciao Claude plugin does not match the validated content");
    }
    validate_private_file(
        &target
            .join(MANIFEST_DIRECTORY_NAME)
            .join(MANIFEST_FILE_NAME),
    )?;
    validate_private_file(&target.join(HOOKS_DIRECTORY_NAME).join(HOOKS_FILE_NAME))?;
    Ok(())
}

fn secure_plugin_tree(target: &Path) -> Result<()> {
    for directory in [
        target.to_path_buf(),
        target.join(MANIFEST_DIRECTORY_NAME),
        target.join(HOOKS_DIRECTORY_NAME),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    for file in [
        target
            .join(MANIFEST_DIRECTORY_NAME)
            .join(MANIFEST_FILE_NAME),
        target.join(HOOKS_DIRECTORY_NAME).join(HOOKS_FILE_NAME),
    ] {
        fs::set_permissions(file, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn remove_stale_owned_tree(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    read_existing_owned(path).context("refuse unsafe stale Ciao Claude plugin tree")?;
    remove_owned_tree(path)
}

fn remove_owned_tree(path: &Path) -> Result<()> {
    read_existing_owned(path)?.ok_or_else(|| anyhow!("Ciao Claude plugin tree disappeared"))?;
    fs::remove_file(path.join(MANIFEST_DIRECTORY_NAME).join(MANIFEST_FILE_NAME))?;
    fs::remove_file(path.join(HOOKS_DIRECTORY_NAME).join(HOOKS_FILE_NAME))?;
    fs::remove_dir(path.join(MANIFEST_DIRECTORY_NAME))?;
    fs::remove_dir(path.join(HOOKS_DIRECTORY_NAME))?;
    fs::remove_dir(path)?;
    Ok(())
}

fn validate_expected(expected: &PluginFiles) -> Result<()> {
    for bytes in [&expected.manifest, &expected.hooks] {
        if bytes.is_empty() || bytes.len() as u64 > MAX_PLUGIN_FILE_BYTES || !contains_marker(bytes)
        {
            bail!("embedded Ciao Claude plugin failed static validation");
        }
        let _: Value = serde_json::from_slice(bytes)?;
    }
    let hooks = std::str::from_utf8(&expected.hooks)?;
    for required in [
        "SessionStart",
        "UserPromptSubmit",
        "MessageDisplay",
        "Notification",
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        // Quoted: a bare `Stop` is a substring of `StopFailure`, so the loose spelling would
        // pass on a plugin that dropped the turn-close edge.
        "\"Stop\"",
        "SessionEnd",
        "__claude-hook",
    ] {
        if !hooks.contains(required) {
            bail!("embedded Ciao Claude plugin omitted a required hook");
        }
    }
    for forbidden in [
        "PermissionRequest",
        "AskUserQuestion",
        "ExitPlanMode",
        "Elicitation",
        "additionalContext",
        "terminalSequence",
    ] {
        if hooks.contains(forbidden) {
            bail!("embedded Ciao Claude plugin advertised an unqualified control surface");
        }
    }
    Ok(())
}

fn ensure_owned_directory(path: &Path, label: &str) -> Result<()> {
    if path.exists() {
        validate_owned_directory(path, label)?;
        return Ok(());
    }
    fs::create_dir(path).with_context(|| format!("create {label} directory"))?;
    validate_owned_directory(path, label)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn validate_owned_directory(path: &Path, label: &str) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {label} directory"))?;
    validate_directory_metadata(&metadata, label)
}

fn validate_directory_metadata(metadata: &fs::Metadata, label: &str) -> Result<()> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != current_uid() {
        bail!("{label} location must be a same-user regular directory");
    }
    Ok(())
}

/// The same rule the hook path has always run on, applied where the install decides.
///
/// This gate used to demand exact equality with the pin while `claude_hook.rs` accepted any
/// later patch of the same minor, so a machine could be refused the plugin it would then have
/// been served correctly. Exactness is also unpayable here: the version comes from the user's
/// own auto-updating Claude, which moved 2.1.220 → 2.1.233 in six days, and a host release per
/// upstream patch is not a schedule anyone can keep. A patch of the same minor changes no hook
/// event name and no payload key this adapter reads.
///
/// The managed runtime deliberately keeps exact equality: it installs its own SDK into a
/// Ciao-owned prefix and digest-verifies the binary before spawning it, so the version is one
/// Ciao chooses, and the check is a security boundary rather than a compatibility guess.
fn claude_version_state(version: &str) -> VendorVersionState {
    classify_vendor_version(version, PINNED_CLAUDE_VERSION)
}

fn require_pinned_claude_version(paths: &CiaoPaths) -> Result<()> {
    match installed_claude_version(paths)? {
        Some(version) if claude_version_state(&version).admitted() => Ok(()),
        Some(version) => bail!(
            "Claude Code {version} is installed, but this Ciao build supports {PINNED_CLAUDE_VERSION} and later releases of the same major version"
        ),
        None => bail!("Claude Code is not available on PATH"),
    }
}

pub(crate) fn installed_claude_version(paths: &CiaoPaths) -> Result<Option<String>> {
    let Some(binary) = claude_binary(paths) else {
        return Ok(None);
    };
    let output = match Command::new(&binary).arg("--version").output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect Claude Code version"),
    };
    Ok(Some(parse_claude_version_output(&output)?))
}

/// `PATH` first, then the per-user location the vendor's own Linux installer writes to.
///
/// A `PATH` lookup alone is right for a login shell and wrong for the daemon, which is exactly
/// who asks: a systemd user unit inherits a minimal `PATH` — `/usr/local/bin:/usr/local/sbin:
/// /usr/bin:/usr/sbin` on Rocky Linux 10 — with no `~/.local/bin` in it. So a correctly
/// installed Claude Code reported as "Claude Code is unavailable", which is a false negative in
/// the first place anyone looks when a session is not showing up.
///
/// Same-user regular files only, and only this one extra path: an absent binary must keep
/// reading as absent rather than as any executable named `claude` that happens to be reachable.
fn claude_binary(paths: &CiaoPaths) -> Option<PathBuf> {
    if Command::new("claude").arg("--version").output().is_ok() {
        return Some(PathBuf::from("claude"));
    }
    let candidate = paths.home.join(".local/bin/claude");
    let metadata = fs::metadata(&candidate).ok()?;
    (metadata.is_file() && metadata.uid() == current_uid()).then_some(candidate)
}

pub(crate) fn parse_claude_version_output(output: &std::process::Output) -> Result<String> {
    if !output.status.success()
        || !output.stderr.is_empty()
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_VERSION_OUTPUT_BYTES
    {
        bail!("Claude Code returned an invalid version response");
    }
    let version = std::str::from_utf8(&output.stdout)?
        .trim()
        .strip_suffix(" (Claude Code)")
        .ok_or_else(|| anyhow!("Claude Code version response has an unknown format"))?;
    if version.is_empty()
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        bail!("Claude Code version response is invalid");
    }
    Ok(version.into())
}

fn current_uid() -> u32 {
    nix::unistd::Uid::effective().as_raw()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    use super::*;

    fn files(home: &Path) -> PluginFiles {
        expected_plugin(&CiaoPaths::for_home(home)).unwrap()
    }

    #[test]
    fn the_install_gate_covers_later_patches_admits_a_minor_as_ahead_and_refuses_a_major() {
        // The install/status path and the hook path must agree. They did not: this gate was
        // `==` while claude_hook.rs ran the range rule, so an auto-updated Claude was refused
        // the plugin that would then have served it. Both now run `classify_vendor_version`.
        use VendorVersionState::{Ahead, Grounded, Unsupported};
        assert_eq!(claude_version_state(PINNED_CLAUDE_VERSION), Grounded);
        assert_eq!(claude_version_state("2.1.233"), Grounded);
        assert_eq!(
            claude_version_state("2.1.221"),
            Unsupported,
            "an older patch"
        );
        // Spec 017 Phase 2, the change that ends going dark: a later 2.x minor is admitted and
        // labeled `ahead` — SemVer promises additivity above 1.0 — where it used to strand
        // every auto-updated user until a Ciao release.
        assert_eq!(
            claude_version_state("2.2.0"),
            Ahead,
            "a minor bump runs ahead"
        );
        assert_eq!(
            claude_version_state("2.9.0"),
            Ahead,
            "any later minor of the major"
        );
        assert_eq!(claude_version_state("3.1.222"), Unsupported, "a major bump");
        assert_eq!(
            claude_version_state("2.1.233-rc1"),
            Unsupported,
            "a prerelease"
        );
        assert_eq!(
            claude_version_state(""),
            Unsupported,
            "an unparseable version"
        );

        // The 2026-08-16 split, fenced. This floor and the managed runtime's exact CLI pin were
        // one constant, so bumping the managed SDK raised the floor and cut off every user
        // between the old value and the new one. These two literals are the band that a managed
        // bump must never take away; if someone re-syncs the pins out of habit, this fails.
        assert_eq!(
            claude_version_state("2.1.222"),
            Grounded,
            "the grounded floor must stay admitted"
        );
        assert_eq!(
            claude_version_state("2.1.232"),
            Grounded,
            "the band below the managed pin must stay admitted"
        );
    }

    #[test]
    fn install_update_and_uninstall_preserve_other_skills() {
        let temporary = tempdir().unwrap();
        let home = temporary.path();
        let skills = home.join(".claude/skills");
        fs::create_dir_all(&skills).unwrap();
        fs::write(skills.join("other-skill.md"), "synthetic unrelated skill").unwrap();
        let target = skills.join(PLUGIN_DIRECTORY_NAME);
        let expected = files(home);

        assert_eq!(
            install_at(&target, &expected).unwrap(),
            ClaudeIntegrationStatus::Installed
        );
        assert_eq!(
            install_at(&target, &expected).unwrap(),
            ClaudeIntegrationStatus::Installed
        );
        assert!(skills.join("other-skill.md").exists());

        // Ownership must survive a pinned Claude version change. Older generated descriptions
        // contain the stable marker plus their former version and remain safe to replace.
        let legacy_marker = "Ciao attached Agent Session hooks for Claude Code 2.1.219";
        let legacy = PluginFiles {
            manifest: String::from_utf8(expected.manifest.clone())
                .unwrap()
                .replace(OWNERSHIP_MARKER, legacy_marker)
                .into_bytes(),
            hooks: String::from_utf8(expected.hooks.clone())
                .unwrap()
                .replace(OWNERSHIP_MARKER, legacy_marker)
                .into_bytes(),
        };
        atomic_write_private(
            &target
                .join(MANIFEST_DIRECTORY_NAME)
                .join(MANIFEST_FILE_NAME),
            &legacy.manifest,
        )
        .unwrap();
        atomic_write_private(
            &target.join(HOOKS_DIRECTORY_NAME).join(HOOKS_FILE_NAME),
            &legacy.hooks,
        )
        .unwrap();
        assert_eq!(read_existing_owned(&target).unwrap().unwrap(), legacy);
        install_at(&target, &expected).unwrap();
        assert_eq!(read_existing_owned(&target).unwrap().unwrap(), expected);

        let mut old = expected.clone();
        old.hooks.extend_from_slice(b"\n");
        atomic_write_private(
            &target.join(HOOKS_DIRECTORY_NAME).join(HOOKS_FILE_NAME),
            &old.hooks,
        )
        .unwrap();
        assert_ne!(read_existing_owned(&target).unwrap().unwrap(), expected);
        install_at(&target, &expected).unwrap();
        assert_eq!(read_existing_owned(&target).unwrap().unwrap(), expected);

        assert!(uninstall_at(&target).unwrap());
        assert!(!uninstall_at(&target).unwrap());
        assert!(skills.join("other-skill.md").exists());
    }

    #[test]
    fn a_stale_install_refreshes_itself_and_an_absent_one_is_left_alone() {
        let temporary = tempdir().unwrap();
        let home = temporary.path();
        let skills = home.join(".claude/skills");
        fs::create_dir_all(&skills).unwrap();
        let target = skills.join(PLUGIN_DIRECTORY_NAME);
        let expected = files(home);

        // Opting in stays the user's decision: a host that never installed stays uninstalled.
        assert!(!refresh_at(&target, &expected).unwrap());
        assert!(!target.exists());

        // An install made by an older Ciao observes an older set of events. Nobody runs a
        // command to fix that, so the daemon does.
        install_at(&target, &expected).unwrap();
        let stale = String::from_utf8(expected.hooks.clone())
            .unwrap()
            .replace("\"Notification\"", "\"SessionStartLegacy\"")
            .into_bytes();
        atomic_write_private(
            &target.join(HOOKS_DIRECTORY_NAME).join(HOOKS_FILE_NAME),
            &stale,
        )
        .unwrap();
        assert!(refresh_at(&target, &expected).unwrap());
        assert_eq!(read_existing_owned(&target).unwrap().unwrap(), expected);

        // A current install is not rewritten, so a restart loop cannot churn the file.
        assert!(!refresh_at(&target, &expected).unwrap());
    }

    #[test]
    fn foreign_entries_and_symlinks_are_never_replaced_or_removed() {
        let temporary = tempdir().unwrap();
        let home = temporary.path();
        let skills = home.join(".claude/skills");
        fs::create_dir_all(&skills).unwrap();
        let target = skills.join(PLUGIN_DIRECTORY_NAME);
        fs::create_dir(&target).unwrap();
        fs::write(target.join("foreign"), "synthetic foreign plugin").unwrap();
        assert!(install_at(&target, &files(home)).is_err());
        assert!(uninstall_at(&target).is_err());
        assert!(target.join("foreign").exists());

        fs::remove_dir_all(&target).unwrap();
        let foreign = home.join("foreign-plugin");
        write_plugin_tree(&foreign, &files(home)).unwrap();
        symlink(&foreign, &target).unwrap();
        assert!(install_at(&target, &files(home)).is_err());
        assert!(uninstall_at(&target).is_err());
        assert!(target.is_symlink());
    }

    #[test]
    fn grounded_generated_plugin_passes_pinned_cli_validation_when_enabled() {
        if std::env::var("CIAO_TEST_CLAUDE_CLI").as_deref() != Ok("1") {
            return;
        }
        assert_eq!(
            installed_claude_version(&CiaoPaths::for_home(
                std::env::var("HOME").unwrap_or_else(|_| "/nonexistent".into())
            ))
            .unwrap()
            .as_deref(),
            Some(PINNED_CLAUDE_VERSION)
        );
        let temporary = tempdir().unwrap();
        let plugin = temporary.path().join(PLUGIN_DIRECTORY_NAME);
        write_plugin_tree(&plugin, &files(temporary.path())).unwrap();
        let output = Command::new("claude")
            .args(["plugin", "validate"])
            .arg(&plugin)
            .arg("--strict")
            .env("CLAUDE_CONFIG_DIR", temporary.path().join("config"))
            .env("DISABLE_AUTOUPDATER", "1")
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn generated_plugin_is_observation_only_and_uses_stable_binary() {
        let temporary = tempdir().unwrap();
        let expected = files(temporary.path());
        validate_expected(&expected).unwrap();
        let hooks: Value = serde_json::from_slice(&expected.hooks).unwrap();
        let encoded = serde_json::to_string(&hooks).unwrap();
        assert!(encoded.contains("/.local/bin/ciao"));
        assert!(encoded.contains("MessageDisplay"));
        for forbidden in [
            "PermissionRequest",
            "AskUserQuestion",
            "ExitPlanMode",
            "Elicitation",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    /// Spec 019, and the bug it came from. `map_hook_input` had a `Stop` arm from the adapter's
    /// first commit; this list never did, so for months every attached turn opened and none ever
    /// closed — silently, because a hook that is never subscribed reports nothing to miss. The
    /// spelling is quoted: a bare `Stop` is a substring of `StopFailure` and would pass on
    /// exactly the plugin this fences against.
    #[test]
    fn the_plugin_subscribes_the_turn_close_and_static_validation_demands_it() {
        let temporary = tempdir().unwrap();
        let expected = files(temporary.path());
        let hooks: Value = serde_json::from_slice(&expected.hooks).unwrap();
        assert!(hooks["hooks"]["Stop"].is_array());

        let mut without: Value = hooks.clone();
        without["hooks"]
            .as_object_mut()
            .unwrap()
            .remove("Stop")
            .unwrap();
        let stripped = PluginFiles {
            manifest: expected.manifest.clone(),
            hooks: serde_json::to_vec_pretty(&without).unwrap(),
        };
        assert!(
            validate_expected(&stripped).is_err(),
            "a plugin that cannot close a turn must not pass static validation"
        );
    }
}
