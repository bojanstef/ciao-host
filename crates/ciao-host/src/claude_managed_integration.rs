//! Installation of the Ciao-owned managed Claude runtime (Spec 006 §8.5).
//!
//! The pinned Agent SDK is proprietary and is never vendored or redistributed
//! by Ciao: this installs it from npm onto the user's machine, into a
//! Ciao-owned prefix, and verifies the pinned pair by digest before it may be
//! used. Nothing here touches the user's own Claude installation, its
//! configuration, its session files, or the attached integration.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::{
    claude_managed_adapter::PINNED_CLAUDE_SDK_VERSION,
    managed_worker::ManagedRuntime,
    storage::{CiaoPaths, ensure_private_directory},
};

/// The worker entrypoint ships in the Ciao repository and is installed beside
/// the prefix; it is Ciao's own code, not vendor material.
const WORKER_SOURCE: &str = include_str!("../../../integrations/claude/managed-worker/worker.mjs");

pub(crate) fn install_managed_claude(paths: &CiaoPaths) -> Result<()> {
    let prefix = &paths.managed_sdk_prefix;
    ensure_private_directory(prefix).context("create the managed SDK prefix")?;
    if let Some(parent) = paths.managed_worker_entrypoint.parent() {
        ensure_private_directory(parent).context("create the managed worker directory")?;
    }
    std::fs::write(&paths.managed_worker_entrypoint, WORKER_SOURCE)
        .context("install the managed worker entrypoint")?;

    let Some(node) = which_node() else {
        bail!("{}", missing_node_message());
    };
    // Install runs from the user's shell and can see what the daemon cannot:
    // the interpreter's real location and a PATH where Claude's own tools work.
    // The daemon under launchd has only /usr/bin:/bin:/usr/sbin:/sbin.
    let recorded = crate::managed_worker::RecordedRuntime {
        node: node.to_string_lossy().into_owned(),
        path: std::env::var("PATH").unwrap_or_default(),
    };
    std::fs::write(
        crate::managed_worker::runtime_record_file(prefix),
        serde_json::to_vec(&recorded).context("encode the recorded runtime")?,
    )
    .context("record the managed runtime environment")?;
    // A private package.json keeps npm from walking up into the user's projects.
    std::fs::write(
        prefix.join("package.json"),
        serde_json::json!({ "name": "ciao-managed-claude", "private": true }).to_string(),
    )
    .context("prepare the managed SDK prefix")?;
    clear_sdk_tree(prefix)?;
    let status = Command::new("npm")
        .args([
            "install",
            &format!("@anthropic-ai/claude-agent-sdk@{PINNED_CLAUDE_SDK_VERSION}"),
            "--no-audit",
            "--no-fund",
        ])
        .current_dir(prefix)
        .status()
        .context("run npm to install the pinned Claude Agent SDK")?;
    if !status.success() {
        bail!("npm could not install the pinned Claude Agent SDK.");
    }
    // The install is only complete when the pinned pair verifies by digest.
    ManagedRuntime::resolve(prefix, &paths.managed_worker_entrypoint)
        .map_err(|reason| anyhow::anyhow!("the installed Claude runtime is unusable: {reason}"))?;
    // A deliberate reinstall supersedes any self-restore news; stale news is noise.
    let _ = std::fs::remove_file(prefix.join(HEAL_MARKER_FILE));
    Ok(())
}

/// Spec 017 §6: restore the known-good, never accept the drifted. When the pre-spawn digest
/// gate refuses a runtime that a completed install once verified, the daemon gets one attempt
/// per run to put the pinned artifact back — the same `npm install` at the same exact pin into
/// the same Ciao-owned prefix, re-verified by the same gate — before the categorical refusal
/// surfaces as it always did.
///
/// Deliberately not `install_managed_claude`: that runs from the user's shell and re-records
/// the interpreter and `PATH` it can see, and a launchd daemon re-recording its own
/// `/usr/bin:/bin` would break the worker's tools to fix its binary. Restoration preserves the
/// record, and the record is also the eligibility proof — no record means no completed install
/// to restore, and opting in stays the user's act.
///
/// ponytail: one attempt per daemon run, not per cause. A second corruption in one lifetime is
/// a disk or an attacker, not drift, and thrashing npm at it helps neither; a restart re-arms.
pub(crate) fn try_restore_managed_claude_once(sdk_prefix: &Path, worker_entrypoint: &Path) -> bool {
    use std::sync::atomic::{AtomicBool, Ordering};
    static ATTEMPTED_THIS_RUN: AtomicBool = AtomicBool::new(false);
    // Eligibility before the once-guard: a refusal on a never-installed prefix must not spend
    // the one attempt a later real corruption would need.
    let Some((_node, tool_path)) = crate::managed_worker::read_recorded_runtime(sdk_prefix) else {
        return false;
    };
    if ATTEMPTED_THIS_RUN.swap(true, Ordering::SeqCst) {
        return false;
    }
    match restore_at(sdk_prefix, worker_entrypoint, &tool_path) {
        Ok(()) => {
            write_heal_marker(sdk_prefix, "restored", "");
            tracing::info!(
                "managed runtime restored to the pinned install after it changed on disk"
            );
            true
        }
        Err(error) => {
            write_heal_marker(sdk_prefix, "failed", &format!("{error:#}"));
            tracing::warn!(error = %error, "managed runtime self-restore failed");
            false
        }
    }
}

fn restore_at(sdk_prefix: &Path, worker_entrypoint: &Path, tool_path: &str) -> Result<()> {
    ensure_private_directory(sdk_prefix).context("create the managed SDK prefix")?;
    if let Some(parent) = worker_entrypoint.parent() {
        ensure_private_directory(parent).context("create the managed worker directory")?;
    }
    std::fs::write(worker_entrypoint, WORKER_SOURCE)
        .context("restore the managed worker entrypoint")?;
    std::fs::write(
        sdk_prefix.join("package.json"),
        serde_json::json!({ "name": "ciao-managed-claude", "private": true }).to_string(),
    )
    .context("restore the managed SDK prefix")?;
    clear_sdk_tree(sdk_prefix)?;
    let npm = npm_from_recorded_path(tool_path)
        .ok_or_else(|| anyhow::anyhow!("npm was not found on the recorded PATH"))?;
    let status = Command::new(npm)
        .args([
            "install",
            &format!("@anthropic-ai/claude-agent-sdk@{PINNED_CLAUDE_SDK_VERSION}"),
            "--no-audit",
            "--no-fund",
        ])
        // The recorded PATH, exactly as the worker spawn uses it: what worked at install time,
        // not what launchd happens to offer.
        .env("PATH", tool_path)
        .current_dir(sdk_prefix)
        .status()
        .context("run npm to restore the pinned Claude Agent SDK")?;
    if !status.success() {
        bail!("npm could not restore the pinned Claude Agent SDK");
    }
    ManagedRuntime::resolve(sdk_prefix, worker_entrypoint)
        .map_err(|reason| anyhow::anyhow!("the restored runtime is still unusable: {reason}"))?;
    Ok(())
}

/// npm's install of an already-listed exact version no-ops on the package tree without looking
/// at file contents, so a corrupted binary under an intact-looking tree survives it — the
/// tethered-phone walk proved it, first against the self-restore and then against `ciao setup`
/// itself. Both paths clear the tree first; npm re-extracts from its cache, which is the
/// point: fresh bytes, not a tree check.
fn clear_sdk_tree(sdk_prefix: &Path) -> Result<()> {
    let node_modules = sdk_prefix.join("node_modules");
    if node_modules.exists() {
        std::fs::remove_dir_all(&node_modules).context("clear the drifted SDK tree")?;
    }
    Ok(())
}

/// npm resolved the way the shell would, but against the *recorded* install-time PATH — the
/// daemon's own PATH under launchd does not contain it.
fn npm_from_recorded_path(tool_path: &str) -> Option<std::path::PathBuf> {
    std::env::split_paths(tool_path)
        .map(|directory| directory.join("npm"))
        .find(|candidate| candidate.is_file())
}

const HEAL_MARKER_FILE: &str = "ciao-selfheal.json";

fn write_heal_marker(sdk_prefix: &Path, outcome: &str, detail: &str) {
    let marker = serde_json::json!({
        "v": 1,
        "outcome": outcome,
        "detail": detail,
        "at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0),
    });
    let _ = crate::storage::atomic_write_private(
        &sdk_prefix.join(HEAL_MARKER_FILE),
        marker.to_string().as_bytes(),
    );
}

/// The status suffix a past self-restore earns, read tolerantly: a missing or unreadable
/// marker is simply no news.
fn heal_marker_note(sdk_prefix: &Path) -> Option<&'static str> {
    let bytes = std::fs::read(sdk_prefix.join(HEAL_MARKER_FILE)).ok()?;
    let marker: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    match marker.get("outcome").and_then(serde_json::Value::as_str) {
        Some("restored") => Some("; restored the pinned install after it changed on disk"),
        Some("failed") => Some("; a self-restore was attempted and failed, run `ciao setup`"),
        _ => None,
    }
}

pub(crate) fn uninstall_managed_claude(paths: &CiaoPaths) -> Result<bool> {
    let mut removed = false;
    for path in [
        paths.managed_sdk_prefix.as_path(),
        managed_root(paths).as_path(),
    ] {
        if path.exists() {
            // Only Ciao-owned material is removed; Claude's own installation,
            // configuration, and session files are never touched.
            std::fs::remove_dir_all(path).with_context(|| {
                format!("remove the Ciao-owned managed directory {}", path.display())
            })?;
            removed = true;
        }
    }
    Ok(removed)
}

pub(crate) fn managed_claude_status(paths: &CiaoPaths) -> String {
    if !paths.managed_worker_entrypoint.is_file() {
        return "not installed".into();
    }
    let note = heal_marker_note(&paths.managed_sdk_prefix).unwrap_or("");
    match ManagedRuntime::resolve(&paths.managed_sdk_prefix, &paths.managed_worker_entrypoint) {
        Ok(runtime) => format!(
            "installed (Claude Code {}, Agent SDK {}){note}",
            runtime.cli_version, runtime.sdk_version
        ),
        Err(reason) => format!("installed but unusable: {reason}{note}"),
    }
}

fn managed_root(paths: &CiaoPaths) -> std::path::PathBuf {
    paths
        .managed_worker_entrypoint
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| paths.managed_sdk_prefix.clone())
}

/// The one remedy this failure offers has to be runnable on the machine reading it. It named
/// Homebrew unconditionally until 2026-08-20, when a Lima run of the launch-list onboarding
/// checks read it on Debian: `x86_64-unknown-linux-gnu` is a released target, so a Linux friend
/// hit the only blocking step of setup and was told to run a macOS package manager.
fn missing_node_message() -> String {
    missing_node_message_for(cfg!(target_os = "macos"))
}

/// Split from the `cfg!` above so both arms are reachable from one test run; a `cfg!` here
/// would leave the Linux wording provable only by cross-compiling the test binary.
fn missing_node_message_for(macos: bool) -> String {
    let remedy = if macos {
        "`brew install node`"
    } else {
        "your package manager (Debian/Ubuntu: `sudo apt install nodejs`)"
    };
    format!(
        "Node.js 18 or newer is required for Ciao-managed Claude sessions but was not found on PATH. Install it with {remedy}, then rerun this command."
    )
}

fn which_node() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join("node"))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    /// The remedy must be runnable where it is read. Homebrew is not on a released Linux host,
    /// and this is the only blocking step in `ciao setup` on a machine without Node.
    #[test]
    fn the_missing_node_remedy_names_this_platforms_installer() {
        let macos = missing_node_message_for(true);
        assert!(macos.contains("Node.js 18 or newer"), "{macos}");
        assert!(macos.contains("brew install node"), "{macos}");

        let linux = missing_node_message_for(false);
        assert!(linux.contains("Node.js 18 or newer"), "{linux}");
        assert!(linux.contains("apt install nodejs"), "{linux}");
        assert!(!linux.contains("brew"), "{linux}");

        // The dispatch is what actually reaches a user; a hardcoded arm passes the two
        // assertions above and still ships the wrong remedy.
        assert_eq!(
            missing_node_message(),
            missing_node_message_for(cfg!(target_os = "macos"))
        );
    }

    /// ADR 004 validation item 8 / Spec 006 §14: the attached read-only path is
    /// byte-for-byte unaffected by managed install and uninstall.
    #[test]
    fn managed_install_and_uninstall_leave_the_attached_plugin_byte_identical() {
        let home = tempdir().unwrap();
        let paths = CiaoPaths::for_home(home.path());
        let claude_config = home.path().join("claude-config");

        // A stand-in for the installed attached plugin tree, digested before and
        // after so any byte change fails this test.
        let plugin_root = claude_config.join("skills/ciao-agent-session/.claude-plugin");
        std::fs::create_dir_all(&plugin_root).unwrap();
        let manifest = plugin_root.join("plugin.json");
        std::fs::write(&manifest, br#"{"name":"ciao-agent-session"}"#).unwrap();
        let hooks = plugin_root.join("hooks.json");
        std::fs::write(&hooks, br#"{"hooks":{}}"#).unwrap();
        let digest = |path: &Path| hex_digest(&std::fs::read(path).unwrap());
        let before = (digest(&manifest), digest(&hooks));

        // Install writes only inside the Ciao-owned prefix. Asserted by path
        // containment rather than by running npm: a unit test must not reach the
        // network, and the property under test is where install may write.
        for target in [&paths.managed_sdk_prefix, &paths.managed_worker_entrypoint] {
            assert!(target.starts_with(&paths.support_dir));
            assert!(!target.starts_with(&claude_config));
        }

        std::fs::create_dir_all(paths.managed_worker_entrypoint.parent().unwrap()).unwrap();
        std::fs::write(&paths.managed_worker_entrypoint, "// fixture").unwrap();
        assert!(uninstall_managed_claude(&paths).unwrap());
        assert_eq!((digest(&manifest), digest(&hooks)), before);
        assert!(manifest.exists() && hooks.exists());
    }

    fn hex_digest(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn status_is_categorical_and_uninstall_only_removes_ciao_material() {
        let home = tempdir().unwrap();
        let paths = CiaoPaths::for_home(home.path());
        assert_eq!(managed_claude_status(&paths), "not installed");

        // A worker present without a verifiable SDK is explicitly unusable
        // rather than silently treated as ready.
        std::fs::create_dir_all(paths.managed_worker_entrypoint.parent().unwrap()).unwrap();
        std::fs::write(&paths.managed_worker_entrypoint, "// fixture").unwrap();
        assert!(managed_claude_status(&paths).starts_with("installed but unusable"));

        // A neighbouring Claude-owned file is never removed by uninstall.
        let vendor_file = paths.support_dir.join("claude-plugin-marker");
        std::fs::write(&vendor_file, "vendor").unwrap();
        assert!(uninstall_managed_claude(&paths).unwrap());
        assert!(!paths.managed_worker_entrypoint.exists());
        assert!(vendor_file.exists());
        assert!(!uninstall_managed_claude(&paths).unwrap());
    }

    #[test]
    fn npm_resolves_from_the_recorded_path_only() {
        let temp = tempdir().unwrap();
        let with_npm = temp.path().join("tools");
        std::fs::create_dir_all(&with_npm).unwrap();
        std::fs::write(with_npm.join("npm"), "#!/bin/sh\n").unwrap();
        let recorded = format!("/nonexistent-fixture-dir:{}", with_npm.display());
        assert_eq!(
            npm_from_recorded_path(&recorded),
            Some(with_npm.join("npm"))
        );
        assert_eq!(npm_from_recorded_path("/nonexistent-fixture-dir"), None);
    }

    #[test]
    fn heal_markers_read_back_as_status_suffixes_and_garbage_reads_as_nothing() {
        let temp = tempdir().unwrap();
        assert_eq!(heal_marker_note(temp.path()), None, "no marker, no news");
        write_heal_marker(temp.path(), "restored", "");
        assert_eq!(
            heal_marker_note(temp.path()),
            Some("; restored the pinned install after it changed on disk")
        );
        write_heal_marker(
            temp.path(),
            "failed",
            "npm was not found on the recorded PATH",
        );
        assert_eq!(
            heal_marker_note(temp.path()),
            Some("; a self-restore was attempted and failed, run `ciao setup`")
        );
        std::fs::write(temp.path().join(HEAL_MARKER_FILE), b"not json").unwrap();
        assert_eq!(
            heal_marker_note(temp.path()),
            None,
            "corrupt reads as absent"
        );
    }

    /// Spec 017 §6, the whole decision surface of the one-shot restore. One test on purpose:
    /// the once-guard is process-wide, so exactly one test may spend the attempt — and the
    /// ineligible case is asserted first precisely because eligibility must not spend it.
    #[test]
    fn the_restore_runs_once_needs_a_record_and_writes_its_outcome() {
        let temp = tempdir().unwrap();
        let prefix = temp.path().join("sdk");
        std::fs::create_dir_all(&prefix).unwrap();
        let entrypoint = temp.path().join("managed/worker.mjs");

        // No runtime record: not eligible, no attempt spent, no marker invented.
        assert!(!try_restore_managed_claude_once(&prefix, &entrypoint));
        assert_eq!(heal_marker_note(&prefix), None);

        // A record whose PATH holds no npm: the attempt runs, fails at npm resolution, and
        // says so durably. The fake node file satisfies the record's own validation.
        let node = temp.path().join("node");
        std::fs::write(&node, "#!/bin/sh\n").unwrap();
        std::fs::write(
            crate::managed_worker::runtime_record_file(&prefix),
            serde_json::json!({
                "node": node.to_string_lossy(),
                "path": "/nonexistent-fixture-dir",
            })
            .to_string(),
        )
        .unwrap();
        assert!(!try_restore_managed_claude_once(&prefix, &entrypoint));
        assert_eq!(
            heal_marker_note(&prefix),
            Some("; a self-restore was attempted and failed, run `ciao setup`")
        );
        assert!(
            entrypoint.is_file(),
            "the worker source was rewritten before npm failed"
        );

        // The one attempt is spent: eligible or not, nothing further runs this process.
        std::fs::remove_file(prefix.join(HEAL_MARKER_FILE)).unwrap();
        assert!(!try_restore_managed_claude_once(&prefix, &entrypoint));
        assert_eq!(
            heal_marker_note(&prefix),
            None,
            "no second attempt, no new marker"
        );
    }
}
