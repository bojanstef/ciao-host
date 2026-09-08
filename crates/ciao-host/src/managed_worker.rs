//! Spec 006 §8.2/§9.1: spawning and supervising the pinned managed worker.
//!
//! The daemon owns the worker process. It resolves and digest-verifies the
//! pinned SDK pair, spawns the Ciao-owned worker entrypoint with a minimal
//! environment and a one-time registration token, waits for the worker to
//! register over the existing agent bridge, and reaps the process afterwards.
//! Credentials, prompts, and vendor payloads never pass through this module.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use rand::random;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};

use crate::claude_managed_adapter::{PINNED_CLAUDE_SDK_VERSION, PINNED_MANAGED_CLI_VERSION};

/// Spec 006 §12 worker bounds.
#[allow(dead_code)] // enforced with the registration deadline below
pub(crate) const SPAWN_TOKEN_VALIDITY: Duration = Duration::from_secs(30);
#[allow(dead_code)] // enforced when the launcher awaits registration
pub(crate) const REGISTRATION_DEADLINE: Duration = Duration::from_secs(30);
pub(crate) const GRACEFUL_STOP: Duration = Duration::from_secs(10);

/// Everything the launcher resolved and verified before a spawn is permitted.
#[derive(Debug, Clone)]
pub(crate) struct ManagedRuntime {
    pub(crate) sdk_prefix: PathBuf,
    pub(crate) worker_entrypoint: PathBuf,
    pub(crate) cli_path: PathBuf,
    pub(crate) cli_version: String,
    pub(crate) sdk_version: String,
    /// Absolute path to the Node interpreter, recorded at install time. The
    /// daemon's launchd PATH is minimal and will not find a version-manager
    /// install, so resolving `node` at spawn time is not reliable.
    pub(crate) node_path: PathBuf,
    /// The PATH recorded at install time. The daemon's launchd PATH is
    /// `/usr/bin:/bin:/usr/sbin:/sbin`, which would leave Claude's own tools
    /// unable to find anything the user normally has.
    pub(crate) tool_path: String,
}

/// Environment facts captured at install time, when Ciao is running from the
/// user's shell and can see what the daemon later cannot.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RecordedRuntime {
    pub(crate) node: String,
    pub(crate) path: String,
}

/// Digest verification reads and hashes a ~257 MB binary, which is far too slow
/// to repeat on every start. The result is memoized against the file's identity,
/// so a changed or replaced binary is always re-verified.
static VERIFIED_BINARIES: Mutex<Option<(PathBuf, u64, i64, String)>> = Mutex::new(None);

fn binary_identity(path: &Path) -> Option<(u64, i64)> {
    let metadata = std::fs::metadata(path).ok()?;
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    Some((metadata.len(), modified))
}

impl ManagedRuntime {
    /// Resolves the Ciao-owned SDK prefix and verifies the pinned pair by
    /// digest. Any mismatch refuses categorically rather than running an
    /// unverified binary.
    pub(crate) fn resolve(
        sdk_prefix: &Path,
        worker_entrypoint: &Path,
    ) -> Result<Self, &'static str> {
        if !worker_entrypoint.is_file() {
            return Err("runtime_unavailable");
        }
        let wrapper = sdk_prefix
            .join("node_modules")
            .join("@anthropic-ai/claude-agent-sdk");
        let manifest_path = wrapper.join("manifest.json");
        let package_path = wrapper.join("package.json");
        if !manifest_path.is_file() || !package_path.is_file() {
            return Err("runtime_unavailable");
        }

        #[derive(Deserialize)]
        struct Package {
            version: String,
        }
        #[derive(Deserialize)]
        struct Platform {
            checksum: String,
        }
        #[derive(Deserialize)]
        struct Manifest {
            version: String,
            platforms: HashMap<String, Platform>,
        }

        let package: Package = read_json(&package_path).ok_or("runtime_unavailable")?;
        let manifest: Manifest = read_json(&manifest_path).ok_or("runtime_unavailable")?;
        if package.version != PINNED_CLAUDE_SDK_VERSION
            || manifest.version != PINNED_MANAGED_CLI_VERSION
        {
            return Err("unsupported_version");
        }
        let platform = current_platform_token().ok_or("runtime_unavailable")?;
        let expected = manifest
            .platforms
            .get(platform)
            .map(|entry| entry.checksum.clone())
            .ok_or("runtime_unavailable")?;
        let cli_path = sdk_prefix
            .join("node_modules")
            .join(format!("@anthropic-ai/claude-agent-sdk-{platform}"))
            .join("claude");
        let identity = binary_identity(&cli_path).ok_or("runtime_unavailable")?;
        let cached = {
            let guard = VERIFIED_BINARIES.lock();
            guard
                .as_ref()
                .is_some_and(|(path, size, modified, digest)| {
                    path == &cli_path
                        && *size == identity.0
                        && *modified == identity.1
                        && digest == &expected
                })
        };
        if !cached {
            let bytes = std::fs::read(&cli_path).map_err(|_| "runtime_unavailable")?;
            if hex(&Sha256::digest(&bytes)) != expected {
                return Err("unsupported_version");
            }
            *VERIFIED_BINARIES.lock() =
                Some((cli_path.clone(), identity.0, identity.1, expected.clone()));
        }
        // Interpreter and PATH are recorded at install time; without them the
        // runtime is unusable rather than silently falling back to a lookup
        // that works in a shell and fails under launchd.
        let (node_path, tool_path) =
            read_recorded_runtime(sdk_prefix).ok_or("runtime_unavailable")?;
        Ok(Self {
            sdk_prefix: sdk_prefix.to_owned(),
            worker_entrypoint: worker_entrypoint.to_owned(),
            cli_path,
            cli_version: PINNED_MANAGED_CLI_VERSION.into(),
            sdk_version: PINNED_CLAUDE_SDK_VERSION.into(),
            node_path,
            tool_path,
        })
    }
}

/// Where the install step records the environment facts it verified.
pub(crate) fn runtime_record_file(sdk_prefix: &Path) -> PathBuf {
    sdk_prefix.join("ciao-runtime.json")
}

pub(crate) fn read_recorded_runtime(sdk_prefix: &Path) -> Option<(PathBuf, String)> {
    let recorded: RecordedRuntime = read_json(&runtime_record_file(sdk_prefix))?;
    let node = PathBuf::from(recorded.node.trim());
    node.is_file().then_some((node, recorded.path))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn current_platform_token() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("macos", "x86_64") => Some("darwin-x64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        ("linux", "x86_64") => Some("linux-x64"),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A spawned worker the daemon supervises. Dropping the handle never orphans a
/// worker: `stop` terminates it and the reaper observes the exit.
#[derive(Debug)]
pub(crate) struct WorkerProcess {
    child: Child,
    pub(crate) spawn_token: String,
}

#[derive(Debug, Default)]
pub(crate) struct WorkerTable {
    workers: Mutex<HashMap<String, WorkerProcess>>,
}

impl WorkerTable {
    /// Spawns the worker with a minimal environment. The registration token
    /// travels in the environment rather than argv so it never appears in a
    /// process listing.
    // ponytail: nine spawn parameters, all required by the worker's command line. A parameter
    // struct would move the same fields behind a name that adds nothing.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn(
        &self,
        runtime: &ManagedRuntime,
        session_id: &str,
        workspace_path: &Path,
        workspace_label: &str,
        socket_path: &Path,
        resume_vendor_session: Option<&str>,
        permission_mode: Option<&str>,
        model: Option<&str>,
    ) -> Result<String> {
        let spawn_token = format!("{:032x}", random::<u128>());
        let mut command = Command::new(&runtime.node_path);
        command
            .arg(&runtime.worker_entrypoint)
            .current_dir(workspace_path)
            // The daemon's environment is inherited deliberately. Claude
            // authenticates from the user's own credential state, and clearing
            // the environment strips what it needs to find it: dropping USER
            // alone makes an otherwise valid login fail to refresh. Ciao still
            // never reads, stores, or transports the credentials themselves.
            .env("PATH", &runtime.tool_path)
            // Spec 017 §6: the pinned artifact must not mutate. Inherited by the SDK and the
            // bundled CLI it spawns; without it a self-update rewrites the binary in place and
            // the digest gate above then refuses to spawn — a self-inflicted outage whose
            // cause reads as corruption. Probes and the plugin-validate test already set it.
            .env("DISABLE_AUTOUPDATER", "1")
            .env("CIAO_MANAGED_SOCKET", socket_path)
            .env("CIAO_MANAGED_SDK_PREFIX", &runtime.sdk_prefix)
            .env("CIAO_MANAGED_SESSION_ID", session_id)
            .env("CIAO_MANAGED_SPAWN_TOKEN", &spawn_token)
            .env("CIAO_MANAGED_WORKSPACE_LABEL", workspace_label)
            .env("CIAO_MANAGED_CLI_VERSION", &runtime.cli_version)
            .env("CIAO_MANAGED_SDK_VERSION", &runtime.sdk_version)
            .env("CIAO_MANAGED_CLI_PATH", &runtime.cli_path)
            .stdin(Stdio::null())
            // Worker output is discarded: it must never become a content path.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if let Some(resume) = resume_vendor_session {
            command.env("CIAO_MANAGED_RESUME_SESSION_ID", resume);
        }
        // Absent unless the conversation being resumed recorded one, so the worker's own
        // default is what an unset variable means — never a mode invented here.
        if let Some(mode) = permission_mode {
            command.env("CIAO_MANAGED_PERMISSION_MODE", mode);
        }
        // Same contract: absent means the worker picks, which is what an unset variable meant
        // before this existed. Never a model chosen here.
        if let Some(model) = model {
            command.env("CIAO_MANAGED_MODEL", model);
        }
        let child = command.spawn().context("spawn managed worker")?;
        self.workers.lock().insert(
            session_id.to_owned(),
            WorkerProcess {
                child,
                spawn_token: spawn_token.clone(),
            },
        );
        Ok(spawn_token)
    }

    /// Confirms a registration's one-time token and consumes it, so a replayed
    /// or foreign registration cannot bind to a live worker.
    pub(crate) fn consume_token(&self, session_id: &str, token: &str) -> bool {
        let mut workers = self.workers.lock();
        let Some(worker) = workers.get_mut(session_id) else {
            return false;
        };
        if worker.spawn_token.is_empty() || worker.spawn_token != token {
            return false;
        }
        worker.spawn_token.clear();
        true
    }

    /// Graceful stop, then termination. Returns once the process is reaped so
    /// single ownership of the vendor session is not left to chance.
    pub(crate) async fn stop(&self, session_id: &str) -> bool {
        let Some(mut worker) = self.workers.lock().remove(session_id) else {
            return false;
        };
        if let Some(pid) = worker.child.id().and_then(|pid| i32::try_from(pid).ok()) {
            // SIGTERM lets the worker close its SDK query and socket cleanly.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        match tokio::time::timeout(GRACEFUL_STOP, worker.child.wait()).await {
            Ok(_) => true,
            Err(_) => {
                let _ = worker.child.kill().await;
                let _ = worker.child.wait().await;
                true
            }
        }
    }

    /// Reaps workers that exited on their own. Returns the sessions whose
    /// worker is gone so the directory can record a truthful stored reason.
    pub(crate) fn reap(&self) -> Vec<(String, bool)> {
        let mut workers = self.workers.lock();
        let mut exited = Vec::new();
        workers.retain(|session_id, worker| match worker.child.try_wait() {
            Ok(Some(status)) => {
                exited.push((session_id.clone(), !status.success()));
                false
            }
            Ok(None) => true,
            Err(_) => {
                exited.push((session_id.clone(), true));
                false
            }
        });
        exited
    }
}

/// Best-effort foreign-owner evidence (Spec 006 §8.4). Grounded in the managed
/// conformance run: the vendor enforces no ownership, so Ciao looks for a
/// same-user process explicitly resuming this vendor session. Absence of
/// evidence never proves exclusivity, and this probe may only refuse.
/// Whether some *other* process is holding this conversation.
///
/// `ignoring` is the one process the caller is about to end itself. A takeover's whole job is to
/// close the terminal Claude and continue its conversation, and `PromotionTarget` names that
/// process — so counting it here refused the takeover for the existence of the very thing the
/// takeover removes. It only ever bit when the conversation had been opened with an explicit
/// `claude --resume <id>`, because that is what puts the session ID on a command line for this
/// scan to find; a plain `claude` never matched itself.
pub(crate) async fn foreign_owner_evidence(vendor_session_id: &str, ignoring: Option<u32>) -> bool {
    if vendor_session_id.is_empty() {
        return false;
    }
    let Ok(output) = Command::new("/bin/ps")
        .args(["-axo", "pid=,command="])
        .output()
        .await
    else {
        return false;
    };
    let Ok(listing) = String::from_utf8(output.stdout) else {
        return false;
    };
    has_foreign_owner(&listing, vendor_session_id, ignoring)
}

/// The rule, over a process listing rather than over the machine.
///
/// Split out so it can be tested at all. The `claude` substring is loose enough that any command
/// line mentioning a `.claude` path matches it — a test that shelled out to the real `ps` was
/// answered by the shell running the test, whose command line held both that path and the
/// sentinel session ID the test had just written. Against a real 36-character session ID the
/// looseness is harmless, since a line has to carry that too.
///
/// ponytail: substring matching on a `ps` listing, not process ancestry. It holds because the
/// managed prefix is Ciao-owned and fixed; walk ppid to the worker if that stops being true.
fn has_foreign_owner(listing: &str, vendor_session_id: &str, ignoring: Option<u32>) -> bool {
    listing
        .lines()
        .filter(|line| line.contains("claude"))
        // Ciao's own worker resumes the same conversation, so before a spawn every match is
        // foreign, but a live session always matches itself. The worker runs the SDK's copy of
        // the binary out of Ciao's private prefix and a user's `claude` never does, so the
        // path is what separates us from them.
        .filter(|line| !line.contains(MANAGED_PREFIX_MARKER))
        .filter(|line| line.contains(vendor_session_id))
        .any(|line| {
            // `pid command…`. A line whose PID will not parse still counts: this probe is
            // one-sided on purpose, and dropping a line would lose evidence.
            let Some((pid, _)) = line.trim_start().split_once(char::is_whitespace) else {
                return true;
            };
            match (pid.parse::<u32>(), ignoring) {
                (Ok(pid), Some(ignored)) => pid != ignored,
                _ => true,
            }
        })
}

/// Path fragment unique to the SDK binary Ciao's own workers run.
pub(crate) const MANAGED_PREFIX_MARKER: &str = "managed/claude-sdk";

pub(crate) type SharedWorkerTable = Arc<WorkerTable>;

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    /// A takeover ends the terminal it is taking over, so that terminal cannot be the reason it
    /// is refused. Only an explicit `claude --resume <id>` ever put the session ID on a command
    /// line for this scan to match, which is why the false positive stayed hidden.
    #[test]
    fn the_process_a_takeover_ends_is_not_a_foreign_owner() {
        let session = "08805da6-a345-444f-a235-b1fa8eef2235";
        let mine = format!("  4242 claude --resume {session}");
        let theirs = format!("  99999 claude --resume {session}");
        let listing = format!("{mine}\n{theirs}\n");

        assert!(
            !has_foreign_owner(&mine, session, Some(4242)),
            "the only holder being the terminal this takeover ends is not a foreign owner"
        );
        assert!(
            has_foreign_owner(&listing, session, Some(4242)),
            "discounting one process must not discount another Claude holding the same session"
        );
        assert!(
            has_foreign_owner(&mine, session, None),
            "resume has no process of its own to discount, so the same line is evidence"
        );
        assert!(
            !has_foreign_owner(
                &format!("  4242 {MANAGED_PREFIX_MARKER}/claude --resume {session}"),
                session,
                None
            ),
            "Ciao's own worker is never a foreign owner of the conversation it was given"
        );
        assert!(!has_foreign_owner(&listing, "some-other-session", None));
    }

    #[test]
    fn an_absent_or_mismatched_pin_refuses_categorically() {
        let home = tempdir().unwrap();
        let entrypoint = home.path().join("worker.mjs");
        std::fs::write(&entrypoint, "// fixture").unwrap();

        // No prefix at all is a runtime problem, not a version problem.
        assert_eq!(
            ManagedRuntime::resolve(&home.path().join("missing"), &entrypoint).unwrap_err(),
            "runtime_unavailable"
        );
        // A missing entrypoint refuses before anything is executed.
        assert_eq!(
            ManagedRuntime::resolve(home.path(), &home.path().join("absent.mjs")).unwrap_err(),
            "runtime_unavailable"
        );

        // A wrong wrapper version is an unsupported pair.
        let wrapper = home
            .path()
            .join("node_modules")
            .join("@anthropic-ai/claude-agent-sdk");
        std::fs::create_dir_all(&wrapper).unwrap();
        std::fs::write(
            wrapper.join("package.json"),
            serde_json::json!({ "version": "0.0.1" }).to_string(),
        )
        .unwrap();
        std::fs::write(
            wrapper.join("manifest.json"),
            serde_json::json!({ "version": PINNED_MANAGED_CLI_VERSION, "platforms": {} })
                .to_string(),
        )
        .unwrap();
        assert_eq!(
            ManagedRuntime::resolve(home.path(), &entrypoint).unwrap_err(),
            "unsupported_version"
        );

        // The right versions with a wrong binary digest still refuse.
        std::fs::write(
            wrapper.join("package.json"),
            serde_json::json!({ "version": PINNED_CLAUDE_SDK_VERSION }).to_string(),
        )
        .unwrap();
        let platform = current_platform_token().unwrap();
        std::fs::write(
            wrapper.join("manifest.json"),
            serde_json::json!({
                "version": PINNED_MANAGED_CLI_VERSION,
                "platforms": { platform: { "checksum": "00".repeat(32) } },
            })
            .to_string(),
        )
        .unwrap();
        let binary = home
            .path()
            .join("node_modules")
            .join(format!("@anthropic-ai/claude-agent-sdk-{platform}"));
        std::fs::create_dir_all(&binary).unwrap();
        std::fs::write(binary.join("claude"), b"not the pinned binary").unwrap();
        assert_eq!(
            ManagedRuntime::resolve(home.path(), &entrypoint).unwrap_err(),
            "unsupported_version"
        );

        // A verified pair with no recorded interpreter is still unusable: the
        // daemon's launchd PATH will not find a version-manager Node install,
        // so resolving `node` at spawn time is not something we may assume.
        let digest = hex(&Sha256::digest(b"not the pinned binary"));
        std::fs::write(
            wrapper.join("manifest.json"),
            serde_json::json!({
                "version": PINNED_MANAGED_CLI_VERSION,
                "platforms": { platform: { "checksum": digest } },
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            ManagedRuntime::resolve(home.path(), &entrypoint).unwrap_err(),
            "runtime_unavailable"
        );

        // Recording the interpreter completes the install.
        std::fs::write(
            runtime_record_file(home.path()),
            serde_json::json!({ "node": "/usr/bin/env", "path": "/usr/bin:/bin" }).to_string(),
        )
        .unwrap();
        let runtime = ManagedRuntime::resolve(home.path(), &entrypoint).unwrap();
        assert_eq!(runtime.cli_version, PINNED_MANAGED_CLI_VERSION);
        assert_eq!(runtime.sdk_version, PINNED_CLAUDE_SDK_VERSION);
        assert_eq!(runtime.node_path, PathBuf::from("/usr/bin/env"));
        assert_eq!(runtime.tool_path, "/usr/bin:/bin");

        // A recorded path that no longer exists is refused rather than spawned.
        std::fs::write(
            runtime_record_file(home.path()),
            serde_json::json!({ "node": "/nonexistent/node", "path": "/usr/bin" }).to_string(),
        )
        .unwrap();
        assert_eq!(
            ManagedRuntime::resolve(home.path(), &entrypoint).unwrap_err(),
            "runtime_unavailable"
        );
    }

    #[tokio::test]
    async fn spawn_tokens_are_single_use_and_workers_are_reaped() {
        let home = tempdir().unwrap();
        let entrypoint = home.path().join("worker.mjs");
        // A script that exits nonzero stands in for a crashed SDK worker; it is
        // run through `env false` so the test needs no Node install.
        std::fs::write(&entrypoint, "process.exit(3)").unwrap();
        let runtime = ManagedRuntime {
            sdk_prefix: home.path().to_owned(),
            worker_entrypoint: entrypoint,
            cli_path: home.path().join("claude"),
            cli_version: PINNED_MANAGED_CLI_VERSION.into(),
            sdk_version: PINNED_CLAUDE_SDK_VERSION.into(),
            node_path: PathBuf::from("/usr/bin/env"),
            tool_path: "/usr/bin:/bin".into(),
        };
        let table = WorkerTable::default();
        let token = table
            .spawn(
                &runtime,
                "session-a",
                home.path(),
                "workspace",
                &home.path().join("agent.sock"),
                None,
                None,
                None,
            )
            .unwrap();

        // The token authenticates exactly one registration.
        assert!(!table.consume_token("session-a", "wrong-token"));
        assert!(table.consume_token("session-a", &token));
        assert!(!table.consume_token("session-a", &token));
        assert!(!table.consume_token("session-missing", &token));

        // A nonzero exit is reported as a crash and the entry is removed.
        let exited = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let exited = table.reap();
                if !exited.is_empty() {
                    return exited;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(exited, vec![("session-a".to_owned(), true)]);
        // The entry is gone, so a second reap reports nothing and a stale token
        // can no longer bind.
        assert!(table.reap().is_empty());
        assert!(!table.consume_token("session-a", &token));
    }
}
