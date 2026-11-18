//! Fresh, point-in-time Codex main-image/version evidence, not recovery or route authority.
//!
//! Callers already owe known hook-authenticated backend lineage and a fresh unique TUI join.
//! Same-PID exec preserves kernel identity: fresh dynamic checks are mandatory at use. Endpoint
//! checks do not exclude intervening A→B→A exec. No TTL, path cache or old-route continuity.
//! macOS supports native thin arm64 bare executables on local APFS. Linux reuses the existing
//! kernel-held ELF image/cache rule inside a killable custodian and a directly owned launcher.
//! Existing hooks remain unchanged; neither platform has a PATH/old-version fallback.
use crate::storage::CiaoPaths;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexVersion(String);
impl CodexVersion {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    #[cfg(any(target_os = "macos", target_os = "linux", test))]
    fn parse(output: &[u8]) -> Option<Self> {
        use std::os::unix::process::ExitStatusExt;
        let version = crate::codex_hook::parse_codex_version_output(&std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: output.to_vec(),
            stderr: Vec::new(),
        })
        .ok()?;
        let (major, minor, patch) = crate::agent_protocol::parse_version(&version)?;
        let canonical = format!("{major}.{minor}.{patch}");
        (output == format!("codex-cli {canonical}\n").as_bytes()).then_some(Self(canonical))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NativeArchitecture {
    Arm64,
    X86_64,
}

/// No pathname is retained as authority. Revalidate against this exact backend before use;
/// version compatibility/floor/carry policy remains the caller's separate decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCodexImage {
    version: CodexVersion,
    architecture: NativeArchitecture,
    #[cfg(target_os = "macos")]
    backend: ciao_native_process::image::Backend,
    #[cfg(target_os = "macos")]
    code_hash: ciao_native_process::image::CodeHash,
    #[cfg(target_os = "linux")]
    linux_identity: linux::ImageIdentity,
}
impl VerifiedCodexImage {
    pub fn version(&self) -> &CodexVersion {
        &self.version
    }
    pub fn architecture(&self) -> NativeArchitecture {
        self.architecture
    }
}

pub async fn observe(
    paths: &CiaoPaths,
    pid: u32,
    expected_kernel_identity: &str,
) -> Option<VerifiedCodexImage> {
    #[cfg(target_os = "macos")]
    {
        supervision::observe(paths, pid, expected_kernel_identity).await
    }
    #[cfg(target_os = "linux")]
    {
        linux::observe(paths, pid, expected_kernel_identity).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (paths, pid, expected_kernel_identity);
        None
    }
}
pub async fn revalidate(
    paths: &CiaoPaths,
    pid: u32,
    expected_kernel_identity: &str,
    image: &VerifiedCodexImage,
) -> bool {
    #[cfg(target_os = "macos")]
    {
        supervision::revalidate(paths, pid, expected_kernel_identity, image).await
    }
    #[cfg(target_os = "linux")]
    {
        linux::revalidate(paths, pid, expected_kernel_identity, image).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (paths, pid, expected_kernel_identity, image);
        false
    }
}

/// Routing composition fixtures use the ordinary built helper, not the libtest executable.
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
pub(crate) async fn observe_fixture(
    paths: &CiaoPaths,
    pid: u32,
    identity: &str,
    executable: std::path::PathBuf,
) -> Option<VerifiedCodexImage> {
    #[cfg(target_os = "linux")]
    use linux as platform;
    #[cfg(target_os = "macos")]
    use supervision as platform;
    platform::observe_using(paths, pid, identity, executable).await
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
pub(crate) async fn revalidate_fixture(
    pid: u32,
    identity: &str,
    image: &VerifiedCodexImage,
    executable: std::path::PathBuf,
) -> bool {
    #[cfg(target_os = "linux")]
    use linux as platform;
    #[cfg(target_os = "macos")]
    use supervision as platform;
    platform::revalidate_using(pid, identity, image, executable).await
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::helper_entry;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod supervision {
    #[cfg(target_os = "macos")]
    use super::*;
    #[cfg(target_os = "macos")]
    use ciao_native_process::image::{self, Backend, Reply, Request, Transaction};
    #[cfg(target_os = "macos")]
    use std::path::PathBuf;
    #[cfg(any(target_os = "macos", test))]
    use std::process::Stdio;
    use std::{process::ExitStatus, time::Duration};
    use tokio::{
        io::AsyncReadExt,
        sync::{Semaphore, oneshot},
        time::Instant,
    };

    #[cfg(any(target_os = "macos", test))]
    use tokio::process::Command;

    // No queue of unbounded copies. Artifact cap (four) is enforced under a filesystem lock in
    // helpers; unknown crash artifacts consume a slot and are never guessed safe to delete.
    pub(super) static OPERATIONS: Semaphore = Semaphore::const_new(2);
    pub(super) const OPERATION_LIMIT: Duration = Duration::from_secs(30);
    #[cfg(target_os = "macos")]
    const CLEANUP_LIMIT: Duration = Duration::from_secs(5);
    #[cfg(target_os = "macos")]
    const STREAM_LIMIT: usize = image::MAX_PROTOCOL;
    #[cfg(target_os = "macos")]
    const VERSION_STREAM_LIMIT: usize = 4096;

    #[cfg(target_os = "macos")]
    pub(super) async fn observe(
        paths: &CiaoPaths,
        pid: u32,
        identity: &str,
    ) -> Option<VerifiedCodexImage> {
        // Ciao's own executable, never the candidate path or PATH lookup.
        observe_using(paths, pid, identity, std::env::current_exe().ok()?).await
    }

    #[cfg(target_os = "macos")]
    pub(super) async fn observe_using(
        paths: &CiaoPaths,
        pid: u32,
        identity: &str,
        executable: PathBuf,
    ) -> Option<VerifiedCodexImage> {
        let permit = OPERATIONS.try_acquire().ok()?;
        if !ciao_native_process::can_reap_probe_children() {
            return None;
        }
        if identity.len() > 64 || pid == 0 {
            return None;
        }
        let backend = Backend {
            pid,
            identity: identity.to_owned(),
        };
        let owner_pid = std::process::id();
        let transaction = Transaction {
            root: paths.run_dir.join("native-codex-image-v1"),
            nonce: format!("{:032x}", rand::random::<u128>()),
            owner: Backend {
                pid: owner_pid,
                identity: ciao_native_process::native_identity(owner_pid)?,
            },
        };
        let (cancel, mut cancellation) = oneshot::channel::<()>();
        // Dropping the caller's future closes cancel. The task retains sole child ownership until
        // kill/wait and bounded cleanup finish. No abort-on-drop JoinHandle or uncancellable FFI.
        let task = tokio::spawn(async move {
            let _permit = permit;
            let deadline = Instant::now() + OPERATION_LIMIT;
            let result = observe_inner(
                &executable,
                &transaction,
                backend,
                deadline,
                &mut cancellation,
            )
            .await;
            let clean = helper(
                &executable,
                &Request::Cleanup { transaction },
                Instant::now() + CLEANUP_LIMIT,
                None,
                false,
            )
            .await;
            if matches!(
                clean.and_then(|b| serde_json::from_slice::<Reply>(&b).ok()),
                Some(Reply::Clean {})
            ) {
                result
            } else {
                None
            }
        });
        // If the kernel delays a SIGKILL reap (e.g. uninterruptible I/O), the caller still has
        // a deadline. The detached task retains the child AND concurrency permit until reaping;
        // it cannot signal a reused PID or admit an unbounded queue of stuck cleanup work.
        let result = tokio::time::timeout(OPERATION_LIMIT + CLEANUP_LIMIT, task)
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
        drop(cancel);
        result
    }
    #[cfg(target_os = "macos")]
    async fn observe_inner(
        executable: &PathBuf,
        transaction: &Transaction,
        backend: Backend,
        deadline: Instant,
        cancellation: &mut oneshot::Receiver<()>,
    ) -> Option<VerifiedCodexImage> {
        let bytes = helper(
            executable,
            &Request::Prepare {
                transaction: transaction.clone(),
                backend: backend.clone(),
            },
            deadline,
            Some(cancellation),
            false,
        )
        .await?;
        let Reply::Prepared { snapshot } = serde_json::from_slice::<Reply>(&bytes).ok()? else {
            return None;
        };
        if snapshot.transaction != *transaction
            || snapshot.backend != backend
            || image::CodeHash::parse(snapshot.code_hash.as_str()).as_ref()
                != Some(&snapshot.code_hash)
            || snapshot.size == 0
            || snapshot.size > image::MAX_IMAGE
        {
            return None;
        }
        let bytes = helper(
            executable,
            &Request::Execute {
                snapshot: snapshot.clone(),
            },
            deadline,
            Some(cancellation),
            true,
        )
        .await?;
        let version = CodexVersion::parse(&bytes)?;
        let bytes = helper(
            executable,
            &Request::Finish {
                snapshot: snapshot.clone(),
            },
            deadline,
            Some(cancellation),
            false,
        )
        .await?;
        if !matches!(
            serde_json::from_slice::<Reply>(&bytes).ok(),
            Some(Reply::Valid {})
        ) {
            return None;
        }
        Some(VerifiedCodexImage {
            version,
            architecture: NativeArchitecture::Arm64,
            backend,
            code_hash: snapshot.code_hash,
        })
    }
    #[cfg(target_os = "macos")]
    pub(super) async fn revalidate(
        _paths: &CiaoPaths,
        pid: u32,
        identity: &str,
        image: &VerifiedCodexImage,
    ) -> bool {
        let Ok(executable) = std::env::current_exe() else {
            return false;
        };
        revalidate_using(pid, identity, image, executable).await
    }

    #[cfg(target_os = "macos")]
    pub(super) async fn revalidate_using(
        pid: u32,
        identity: &str,
        image: &VerifiedCodexImage,
        executable: PathBuf,
    ) -> bool {
        if !ciao_native_process::can_reap_probe_children()
            || image.backend.pid != pid
            || image.backend.identity != identity
        {
            return false;
        }
        let Ok(permit) = OPERATIONS.try_acquire() else {
            return false;
        };
        let request = Request::Revalidate {
            backend: image.backend.clone(),
            code_hash: image.code_hash.clone(),
        };
        let (cancel, mut cancellation) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _permit = permit;
            let result = helper(
                &executable,
                &request,
                Instant::now() + OPERATION_LIMIT,
                Some(&mut cancellation),
                false,
            )
            .await;
            matches!(
                result.and_then(|b| serde_json::from_slice::<Reply>(&b).ok()),
                Some(Reply::Valid {})
            )
        });
        let result = tokio::time::timeout(OPERATION_LIMIT, task)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);
        drop(cancel);
        result
    }

    #[cfg(target_os = "macos")]
    async fn helper(
        executable: &PathBuf,
        request: &Request,
        deadline: Instant,
        cancellation: Option<&mut oneshot::Receiver<()>>,
        version: bool,
    ) -> Option<Vec<u8>> {
        let text = serde_json::to_string(request).ok()?;
        if text.len() > image::MAX_PROTOCOL || Instant::now() >= deadline {
            return None;
        }
        let mut command = Command::new(executable);
        command
            .arg(image::HELPER_ARGUMENT)
            .arg(text)
            .env_clear()
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // The detached operation owns cancellation/reaping. A wait API error must never
            // cause an implicit Drop signal to a PID whose custody may have been lost.
            .kill_on_drop(false);
        let child = command.spawn().ok()?;
        collect(
            child,
            deadline,
            cancellation,
            if version {
                VERSION_STREAM_LIMIT
            } else {
                STREAM_LIMIT
            },
        )
        .await
    }

    pub(super) async fn collect(
        mut child: tokio::process::Child,
        deadline: Instant,
        mut cancellation: Option<&mut oneshot::Receiver<()>>,
        cap: usize,
    ) -> Option<Vec<u8>> {
        let (Some(mut stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take())
        else {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return None;
        };
        let mut output = Vec::new();
        let mut errors = 0usize;
        let mut out_open = true;
        let mut err_open = true;
        let mut out_buffer = [0u8; 4096];
        let mut err_buffer = [0u8; 4096];
        let mut status: Option<ExitStatus> = None;
        let mut wait_failed = false;
        let accepted = loop {
            if !out_open && !err_open && status.is_some() {
                break true;
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => break false,
                _ = async { match cancellation.as_mut() { Some(receiver) => { let _ = receiver.await; }, None => std::future::pending::<()>().await } } => break false,
                result = child.wait(), if status.is_none() => match result { Ok(value) => status = Some(value), Err(_) => { wait_failed = true; break false; } },
                result = stdout.read(&mut out_buffer), if out_open => match result {
                    Ok(0) => out_open = false,
                    Ok(n) => {
                        if output.len() + n > cap || output.len() + n + errors > cap { break false; }
                        output.extend_from_slice(&out_buffer[..n]);
                    }
                    Err(_) => break false,
                },
                result = stderr.read(&mut err_buffer), if err_open => match result {
                    Ok(0) => err_open = false,
                    Ok(n) => {
                        errors += n;
                        if errors > cap || output.len() + errors > cap { break false; }
                    }
                    Err(_) => break false,
                },
            }
        };
        if status.is_none() && !wait_failed {
            // Sole owner; never signal after a successful wait/reap. SIGKILL, not cooperative
            // termination, covers a blocked helper and ordinary stopped/overflowing probes.
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        // stderr is bounded/drained but never logged or returned. A successful --version must be
        // clean; warnings cannot accidentally become version authority.
        (accepted && errors == 0 && status.is_some_and(|s| s.success())).then_some(output)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        // Supervisor controls execute only fixed system fixtures, never candidate paths.
        async fn run(script: &str, cap: usize, limit: Duration) -> Option<Vec<u8>> {
            let child = Command::new("/bin/sh")
                .arg("-c")
                .arg(script)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            collect(child, Instant::now() + limit, None, cap).await
        }
        #[tokio::test]
        async fn output_exit_and_eof_are_independently_bounded() {
            assert_eq!(
                run("printf 'codex-cli 0.169.0\\n'", 64, Duration::from_secs(2)).await,
                Some(b"codex-cli 0.169.0\n".to_vec())
            );
            assert!(
                run("printf x >&2", 64, Duration::from_secs(2))
                    .await
                    .is_none()
            );
            assert!(
                run("printf ok; exit 1", 64, Duration::from_secs(2))
                    .await
                    .is_none()
            );
            assert!(
                run(
                    "while :; do printf 0123456789; done",
                    64,
                    Duration::from_secs(2)
                )
                .await
                .is_none()
            );
            assert!(
                run(
                    "while :; do printf 0123456789 >&2; done",
                    64,
                    Duration::from_secs(2)
                )
                .await
                .is_none()
            );
            let began = Instant::now();
            assert!(run("printf 0123456789012345678901234567890123456789; printf 0123456789012345678901234567890123456789 >&2; exec /bin/sleep 10", 64, Duration::from_secs(2)).await.is_none());
            assert!(
                began.elapsed() < Duration::from_secs(1),
                "combined overflow must kill before the deadline"
            );
            assert!(
                run(
                    "exec 1>&- 2>&-; exec /bin/sleep 10",
                    64,
                    Duration::from_millis(100)
                )
                .await
                .is_none()
            );
        }
        #[tokio::test]
        async fn cancellation_kills_and_waits_without_eof() {
            for stopped in [false, true] {
                let child = Command::new("/bin/sleep")
                    .arg("10")
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                let pid = child.id().unwrap();
                if stopped {
                    nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid as i32),
                        nix::sys::signal::Signal::SIGSTOP,
                    )
                    .unwrap();
                }
                let (sender, mut receiver) = oneshot::channel();
                drop(sender);
                assert!(
                    collect(
                        child,
                        Instant::now() + Duration::from_secs(2),
                        Some(&mut receiver),
                        64
                    )
                    .await
                    .is_none()
                );
                assert!(crate::process::terminal_identity(pid).await.is_none());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    #[ignore = "requires explicit built Ciao and owned native --backend/--version fixture paths"]
    async fn typed_api_runs_owned_helpers_and_revalidates_current_image() {
        #[cfg(target_os = "linux")]
        use super::linux as platform;
        #[cfg(target_os = "macos")]
        use super::supervision as platform;
        use std::os::unix::fs::DirBuilderExt;
        use tokio::io::AsyncBufReadExt;
        let executable = std::path::PathBuf::from(
            std::env::var_os("CIAO_TEST_NATIVE_IMAGE_CIAO").expect("explicit built Ciao"),
        );
        let fixture = std::path::PathBuf::from(
            std::env::var_os("CIAO_TEST_NATIVE_IMAGE_FIXTURE").expect("explicit owned fixture"),
        );
        assert!(executable.is_absolute() && fixture.is_absolute());
        // Keep a failing test's artifacts rather than deleting potentially live image paths.
        let root = tempfile::tempdir().unwrap().keep();
        let mut paths = CiaoPaths::for_home(&root);
        paths.run_dir = root.join("run");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&paths.run_dir)
            .unwrap();
        async fn backend(fixture: &std::path::Path) -> tokio::process::Child {
            let mut child = tokio::process::Command::new(fixture)
                .arg("--backend")
                .arg(fixture)
                .env_clear()
                .env("LC_ALL", "C")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut reader = tokio::io::BufReader::new(child.stdout.take().unwrap());
            let mut ready = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                reader.read_line(&mut ready),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(ready, "READY\n");
            child
        }
        let mut child = backend(&fixture).await;
        let pid = child.id().unwrap();
        let identity = crate::process::terminal_identity(pid).await.unwrap();
        let image = platform::observe_using(&paths, pid, &identity, executable.clone()).await;
        let positive = match &image {
            Some(image) => {
                platform::revalidate_using(pid, &identity, image, executable.clone()).await
            }
            None => false,
        };
        if let Some(slow) = std::env::var_os("CIAO_TEST_NATIVE_IMAGE_CANCEL_FIXTURE") {
            let slow = std::path::PathBuf::from(slow);
            let marker = std::path::PathBuf::from(
                std::env::var_os("CIAO_TEST_NATIVE_IMAGE_READY")
                    .expect("owned fixture readiness marker"),
            );
            assert!(slow.is_absolute() && marker.is_absolute() && !marker.exists());
            let mut delayed = backend(&slow).await;
            let delayed_pid = delayed.id().unwrap();
            let delayed_identity = crate::process::terminal_identity(delayed_pid)
                .await
                .unwrap();
            let owned_paths = paths.clone();
            let owned_executable = executable.clone();
            let task = tokio::spawn(async move {
                platform::observe_using(
                    &owned_paths,
                    delayed_pid,
                    &delayed_identity,
                    owned_executable,
                )
                .await
            });
            let target_pid = tokio::time::timeout(std::time::Duration::from_secs(8), async {
                loop {
                    if let Ok(text) = tokio::fs::read_to_string(&marker).await
                        && text.ends_with('\n')
                    {
                        let fields: Vec<u32> = text
                            .split_whitespace()
                            .map(|s| s.parse().unwrap())
                            .collect();
                        assert_eq!(fields.len(), 2);
                        assert_eq!(
                            fields[1],
                            std::process::id(),
                            "version target is our direct child"
                        );
                        break fields[0];
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            let directory = paths.run_dir.join(if cfg!(target_os = "macos") {
                "native-codex-image-v1"
            } else {
                "native-codex-linux-v1"
            });
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if crate::process::terminal_identity(target_pid)
                        .await
                        .is_none()
                        && std::fs::read_dir(&directory)
                            .unwrap()
                            .all(|entry| entry.unwrap().file_name() == "lock")
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(
                crate::process::terminal_identity(delayed_pid)
                    .await
                    .is_some()
            );
            delayed.start_kill().unwrap();
            delayed.wait().await.unwrap();
            std::fs::remove_file(marker).unwrap();
            println!(
                "whole observe future cancelled after verified version exec; direct child reaped and transaction removed"
            );
        }
        child.start_kill().unwrap();
        child.wait().await.unwrap();
        let image = image.expect("native image proof");
        assert_eq!(image.version().as_str(), "0.169.0");
        assert!(positive);
        assert!(!platform::revalidate_using(pid, &identity, &image, executable).await);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn version_is_exact_bounded_codex_grammar() {
        for valid in ["codex-cli 0.169.0\n", "codex-cli 1.0.4294967295\n"] {
            assert!(CodexVersion::parse(valid.as_bytes()).is_some());
        }
        for invalid in [
            "0.169.0\n",
            "codex-cli 0.169.0",
            "codex-cli 0.169.0\n\n",
            "codex-cli 00.169.0\n",
            "codex-cli 0.169.0-beta\n",
            "codex-cli 0.169.4294967296\n",
            "codex-cli 0.169.0\r\n",
            "codex-cli 0.169.0\nwarning",
            "codex-cli 0.169.0.1\n",
        ] {
            assert!(
                CodexVersion::parse(invalid.as_bytes()).is_none(),
                "{invalid:?}"
            );
        }
        assert!(CodexVersion::parse(&[255; 10]).is_none());
    }
}
