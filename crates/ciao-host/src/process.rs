//! Generic host process inspection and termination.
//!
//! Stateless and vocabulary-free: a pid goes in, a fact or a signal comes out. Nothing here
//! knows what an Agent Session, a route proof, a vendor dialect, or a workspace is, which is
//! why both the terminal/workspace runtime and the Agent runtime may call down into it.
//!
//! Every `ps` read goes through [`crate::workspace::run_bounded`], so it inherits the same
//! fixed-argv, cleaned-environment, timed, capped-output policy as every other non-PTY
//! provider invocation. This module resolves the `ps` path and owns no other process policy.

use std::{path::Path, time::Duration};

use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};

use crate::workspace::run_bounded;

const MAX_PROCESS_ANCESTRY: usize = 64;

/// How long `request_exit` waits for a SIGTERMed process to go away, as a poll interval and a
/// count rather than a deadline, because the poll is the only way to observe the exit.
const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const EXIT_POLL_ATTEMPTS: usize = 50;

fn ps_binary() -> Option<&'static Path> {
    [Path::new("/bin/ps"), Path::new("/usr/bin/ps")]
        .into_iter()
        .find(|path| path.is_file())
}

/// One bounded `ps -o <field>= -p <pid>` read, trimmed, or `None` if it cannot be read.
///
/// `extra` carries the flags a field needs before `-o` — `-ww` for an unwrapped command line —
/// and is a fixed vocabulary chosen by this module, never remote input.
///
/// `strict` additionally refuses a read where `ps` wrote a diagnostic or printed nothing at all.
/// Fields whose value identifies the process (its argv, its start time) take it; fields where a
/// blank answer is a legitimate one — a process with no controlling terminal — do not.
async fn ps_field(pid: u32, extra: &[&str], field: &str, strict: bool) -> Option<String> {
    let binary = ps_binary()?;
    let pid = pid.to_string();
    let mut args: Vec<&str> = Vec::with_capacity(extra.len() + 4);
    args.extend_from_slice(extra);
    args.extend_from_slice(&["-o", field, "-p", &pid]);
    let output = run_bounded(binary, &args).await.ok()?;
    if !output.status_success
        || output.stdout_truncated
        || (strict && (!output.stderr.is_empty() || output.stdout.is_empty()))
    {
        return None;
    }
    Some(std::str::from_utf8(&output.stdout).ok()?.trim().to_owned())
}

/// The controlling terminal of a process, as `ps` names it and with the `/dev/` prefix it
/// omits. Callers validate the shape; this only reports what was read.
pub(crate) async fn tty(pid: u32) -> Option<String> {
    let token = ps_field(pid, &[], "tty=", false).await?;
    Some(if token.starts_with("/dev/") {
        token
    } else {
        format!("/dev/{token}")
    })
}

/// The full command line of a process, bounded, or `None` if it cannot be read.
pub(crate) async fn command(pid: u32) -> Option<String> {
    ps_field(pid, &["-ww"], "command=", true).await
}

/// When a process started, as `ps` reports it. Bounded to printable ASCII so it can be used as
/// an opaque identity component; `None` when it is unreadable or shaped unexpectedly.
///
/// The bound is the caller's, because what this fingerprint has to fit inside is the caller's
/// identifier vocabulary, not a fact about processes.
pub(crate) async fn start_fingerprint(pid: u32, max_bytes: usize) -> Option<String> {
    let value = ps_field(pid, &[], "lstart=", true).await?;
    (!value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' '))
    .then_some(value)
}

pub(crate) async fn parent(pid: u32) -> Option<u32> {
    ps_field(pid, &[], "ppid=", false).await?.parse().ok()
}

pub(crate) async fn descends_from(mut pid: u32, ancestor: u32) -> bool {
    for _ in 0..MAX_PROCESS_ANCESTRY {
        if pid == ancestor {
            return true;
        }
        let Some(parent) = parent(pid).await else {
            return false;
        };
        if parent == 0 || parent == pid {
            return false;
        }
        pid = parent;
    }
    false
}

pub(crate) fn exists(pid: u32) -> bool {
    i32::try_from(pid)
        .ok()
        .is_some_and(|pid| kill(Pid::from_raw(pid), None).is_ok())
}

/// Asks the process holding a terminal to exit, so its conversation can be taken over or its
/// session closed.
///
/// `SIGTERM`, never `SIGKILL`: the agent exits the way it would on `/exit`, which fires its
/// own end-of-session hook and lets Ciao downgrade the attached row honestly rather than
/// leaving one that still claims to be live. It also gives the agent its chance to finish
/// writing the transcript a managed worker is about to resume.
///
/// Returns whether the process is gone. A terminal that ignores the request refuses the
/// takeover, because the alternative is two processes appending to one conversation.
///
/// Bounded: this runs inside a lifecycle request a phone is waiting on.
pub(crate) async fn request_exit(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    if !exists(pid) {
        return true;
    }
    if kill(Pid::from_raw(raw), Signal::SIGTERM).is_err() {
        // Losing the race between the check and the request is success, not failure.
        return !exists(pid);
    }
    for _ in 0..EXIT_POLL_ATTEMPTS {
        if !exists(pid) {
            return true;
        }
        tokio::time::sleep(EXIT_POLL_INTERVAL).await;
    }
    false
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };

    use tempfile::tempdir;

    use super::*;

    /// Spawns a real process that outlives the test unless signalled, so the process paths are
    /// exercised against a live pid rather than a mock.
    fn spawn_sleeper() -> std::process::Child {
        Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("test sleeper must spawn")
    }

    /// Spawns a terminal owner that installs `trap_action` for SIGTERM, and returns its pid only
    /// once that trap is actually armed.
    ///
    /// Two things here are load-bearing rather than incidental. The owner is deliberately **not**
    /// this test's child: `request_exit`'s real callers ask a user-launched process to exit and it
    /// is reaped by its own parent, whereas a direct child of this test would linger as an
    /// unreaped zombie — which still answers `kill(pid, 0)`, so it would never be observed to exit
    /// and every assertion below would read backwards. And the returned pid is withheld until the
    /// owner writes its ready marker, because a SIGTERM that arrives before the `trap` line runs
    /// is handled by the default action; that race made an owner which ignores SIGTERM look like
    /// one that honours it.
    fn spawn_orphan(directory: &Path, trap_action: &str) -> u32 {
        let script = directory.join("owner.sh");
        let ready = directory.join("ready");
        fs::write(
            &script,
            format!(
                "trap '{trap_action}' TERM\nprintf armed > \"{}\"\nsleep 30 &\nwait\n",
                ready.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let output = Command::new("/bin/sh")
            .args([
                "-c",
                &format!("'{}' >/dev/null 2>&1 & printf %s \"$!\"", script.display()),
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .expect("test orphan must spawn");
        let pid: u32 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .expect("the shell must report the background pid");
        for _ in 0..500 {
            if ready.exists() {
                return pid;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("test orphan {pid} never armed its SIGTERM trap");
    }

    #[test]
    fn existence_tracks_a_real_process_and_refuses_an_impossible_pid() {
        let mut child = spawn_sleeper();
        let pid = child.id();
        assert!(exists(pid), "a just-spawned child must be visible");

        // A pid past i32 cannot name a process at all, and must read as absent rather than as a
        // signal aimed somewhere unintended.
        assert!(!exists(u32::MAX));

        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn request_exit_asks_with_sigterm_so_the_owner_can_flush_its_transcript() {
        let temp = tempdir().unwrap();
        let flushed = temp.path().join("flushed");
        // A SIGKILLed process cannot run a trap, so this marker existing is the proof that the
        // owner was *asked*: that is what lets the agent fire its end-of-session hook and finish
        // writing the transcript a managed worker is about to resume.
        let pid = spawn_orphan(
            temp.path(),
            &format!("printf gone > \"{}\"; exit 0", flushed.display()),
        );
        assert!(exists(pid), "precondition: the terminal owner is live");
        assert!(!flushed.exists(), "precondition: nothing has signalled yet");

        assert!(request_exit(pid).await, "a SIGTERM-able owner must exit");
        assert!(!exists(pid), "the owner must actually be gone");
        assert!(
            flushed.exists(),
            "the owner must have been SIGTERMed, not SIGKILLed"
        );
    }

    #[tokio::test]
    async fn an_owner_that_ignores_the_request_refuses_the_takeover() {
        let temp = tempdir().unwrap();
        // Refusal is the safety property: the alternative to giving up here is two processes
        // appending to one conversation.
        let pid = spawn_orphan(temp.path(), "");
        assert!(exists(pid), "precondition: the terminal owner is live");

        assert!(
            !request_exit(pid).await,
            "an owner still alive after the bounded wait must refuse the takeover"
        );
        assert!(exists(pid), "precondition: it refused by surviving");
        kill(Pid::from_raw(i32::try_from(pid).unwrap()), Signal::SIGKILL).unwrap();
    }

    #[tokio::test]
    async fn an_already_dead_owner_is_success_not_refusal() {
        let mut child = spawn_sleeper();
        let pid = child.id();
        child.kill().unwrap();
        child.wait().unwrap();

        // Racing the owner to its own exit is the common case on a busy host: the takeover asked
        // for something that has already happened, which must not read as "the terminal refused".
        assert!(request_exit(pid).await);
    }

    #[tokio::test]
    async fn ancestry_walks_real_processes_and_stops_at_an_unrelated_one() {
        let mut child = spawn_sleeper();
        let pid = child.id();
        let own = std::process::id();

        assert_eq!(parent(pid).await, Some(own), "the sleeper is our own child");
        assert!(descends_from(pid, own).await);
        assert!(descends_from(own, own).await, "a pid descends from itself");
        // pid 1 descends from nothing this test could have spawned, so it is the one ancestry
        // claim that must come back false however far the walk gets.
        assert!(!descends_from(own, pid).await);

        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn command_reads_the_argv_of_a_live_process_only() {
        let mut child = spawn_sleeper();
        let pid = child.id();

        let line = command(pid).await.expect("a live child has a command line");
        assert!(line.contains("sleep 30"), "unexpected command line: {line}");

        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            command(u32::MAX).await.is_none(),
            "an impossible pid must not yield a command line"
        );
    }

    #[tokio::test]
    async fn start_fingerprint_is_bounded_and_printable() {
        let own = std::process::id();
        let fingerprint = start_fingerprint(own, 64)
            .await
            .expect("this process has a start time");
        assert!(fingerprint.len() <= 64);
        assert!(
            fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        );
        // The bound is the caller's, and a fingerprint that does not fit is refused rather than
        // truncated into something two processes could share.
        assert!(start_fingerprint(own, 1).await.is_none());
    }
}
