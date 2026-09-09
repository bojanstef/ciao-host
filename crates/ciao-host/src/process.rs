//! Generic host process inspection and termination.
//!
//! Stateless and vocabulary-free: a pid goes in, a fact or a signal comes out. Nothing here
//! knows what an Agent Session, a route proof, a vendor dialect, or a workspace is, which is
//! why both the terminal/workspace runtime and the Agent runtime may call down into it.
//!
//! Every `ps` read goes through [`crate::workspace::run_bounded`], so it inherits the same
//! fixed-argv, cleaned-environment, timed, capped-output policy as every other non-PTY
//! provider invocation. Linux start identity instead reads bounded kernel procfs records: `ps`
//! derives its displayed start time from wall time, which can change for a still-live process.

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

/// An opaque process-start identity component, never a display timestamp. Linux uses the boot
/// UUID plus `/proc/<pid>/stat` start ticks, fencing both PID reuse and reboot without wall-clock
/// conversion. Other platforms retain `ps lstart`. Unreadable/malformed Linux records fail closed
/// (no `ps` fallback). Callers must also bind the PID; raw components stay host-local.
///
/// The bound is the caller's, because what this fingerprint has to fit inside is the caller's
/// identifier vocabulary, not a fact about processes.
pub(crate) async fn start_fingerprint(pid: u32, max_bytes: usize) -> Option<String> {
    #[cfg(target_os = "linux")]
    let value = linux_start_fingerprint(Path::new("/proc"), pid).await?;
    #[cfg(not(target_os = "linux"))]
    let value = ps_field(pid, &[], "lstart=", true).await?;
    (!value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' '))
    .then_some(value)
}

#[cfg(any(target_os = "linux", test))]
const MAX_PROC_STAT_BYTES: usize = 4096;

#[cfg(any(target_os = "linux", test))]
async fn linux_start_fingerprint(proc_root: &Path, pid: u32) -> Option<String> {
    use tokio::io::AsyncReadExt;

    async fn read_bounded(path: &Path, cap: usize) -> Option<Vec<u8>> {
        let file = tokio::fs::File::open(path).await.ok()?;
        let mut bytes = Vec::new();
        file.take((cap + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .ok()?;
        (bytes.len() <= cap).then_some(bytes)
    }

    if pid == 0 || i32::try_from(pid).is_err() {
        return None;
    }
    // procfs reports zero file lengths; cap the actual reads rather than trusting metadata.
    tokio::time::timeout(Duration::from_secs(1), async {
        let boot = read_bounded(&proc_root.join("sys/kernel/random/boot_id"), 37).await?;
        let stat =
            read_bounded(&proc_root.join(format!("{pid}/stat")), MAX_PROC_STAT_BYTES).await?;
        linux_identity_from_records(pid, &boot, &stat)
    })
    .await
    .ok()
    .flatten()
}

#[cfg(any(target_os = "linux", test))]
fn linux_identity_from_records(pid: u32, boot: &[u8], stat: &[u8]) -> Option<String> {
    let boot = std::str::from_utf8(boot).ok()?.trim_end_matches('\n');
    if boot.len() != 36
        || !boot.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return None;
    }
    // comm is parenthesized, not escaped: it can contain spaces, ')' and non-UTF-8 bytes.
    // The numeric tail contains no ')', so only the final delimiter identifies field 3.
    if !stat.starts_with(format!("{pid} (").as_bytes()) {
        return None;
    }
    let close = stat.iter().rposition(|&byte| byte == b')')?;
    let tail = std::str::from_utf8(stat.get(close + 1..)?).ok()?;
    if !tail.starts_with(' ') {
        return None;
    }
    let ticks = tail.split_ascii_whitespace().nth(19)?; // field 22, tail begins at 3
    if ticks.is_empty() || !ticks.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let ticks: u64 = ticks.parse().ok()?;
    Some(format!("linux:{}:{ticks}", boot.to_ascii_lowercase()))
}

/// Linux's executable reference names the *mapped image*, even when argv[0] is relative or
/// an updater has unlinked/replaced its original pathname. Keep the procfs reference rather
/// than canonicalizing it to that replaceable pathname. Callers must validate the image at
/// use (and again after a probe); a process may exit or exec between inspections.
///
/// No PATH/argv fallback: those name an installation, not necessarily this running image.
#[cfg(target_os = "linux")]
pub(crate) fn kernel_executable(pid: u32) -> Option<std::path::PathBuf> {
    (pid != 0 && i32::try_from(pid).is_ok())
        .then(|| std::path::PathBuf::from(format!("/proc/{pid}/exe")))
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

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_executable_refers_to_the_running_inode_not_relative_argv_or_replaced_install() {
        use std::os::unix::{fs::MetadataExt, process::CommandExt};
        let home = tempdir().unwrap();
        let binary = home.path().join("codex");
        fs::copy("/bin/sleep", &binary).unwrap();
        let mut child = Command::new(&binary)
            .arg0("codex")
            .arg("30")
            .spawn()
            .unwrap();
        let reference = kernel_executable(child.id()).unwrap();
        let original = fs::metadata(&reference).unwrap();
        assert_eq!(original.ino(), fs::metadata(&binary).unwrap().ino());
        let replacement = home.path().join("replacement");
        fs::copy("/bin/true", &replacement).unwrap();
        fs::rename(&replacement, &binary).unwrap();
        assert_ne!(fs::metadata(&binary).unwrap().ino(), original.ino());
        assert_eq!(fs::metadata(&reference).unwrap().ino(), original.ino());
        assert_eq!(
            fs::read(&reference).unwrap(),
            fs::read("/bin/sleep").unwrap()
        );
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(fs::metadata(&reference).is_err());
        assert!(kernel_executable(0).is_none());
        assert!(kernel_executable(u32::MAX).is_none());
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

    const BOOT_A: &[u8] = b"12345678-1234-1234-1234-123456789abc\n";
    const BOOT_B: &[u8] = b"12345678-1234-1234-1234-123456789abd\n";

    fn stat_record(pid: u32, comm: &[u8], ticks: &str) -> Vec<u8> {
        let mut record = format!("{pid} (").into_bytes();
        record.extend_from_slice(comm);
        // state (3), eighteen fields (4..21), starttime (22), then unrelated fields.
        record.extend_from_slice(format!(") S {}{ticks} 999 888\n", "0 ".repeat(18)).as_bytes());
        record
    }

    #[test]
    fn linux_identity_parses_comm_and_fences_pid_reuse_and_reboot() {
        let first = stat_record(42, b"name with ) ( spaces\n\xff)", "12345");
        let same = stat_record(42, b"renamed", "12345");
        let reused = stat_record(42, b"renamed", "12346");
        let identity = linux_identity_from_records(42, BOOT_A, &first).unwrap();
        assert_eq!(identity, "linux:12345678-1234-1234-1234-123456789abc:12345");
        assert_eq!(
            Some(identity.clone()),
            linux_identity_from_records(42, BOOT_A, &same)
        );
        assert_ne!(
            Some(identity.clone()),
            linux_identity_from_records(42, BOOT_A, &reused)
        );
        assert_ne!(
            Some(identity),
            linux_identity_from_records(42, BOOT_B, &first)
        );
        assert!(linux_identity_from_records(43, BOOT_A, &first).is_none());
        for ticks in ["-1", "+1", "1x", "18446744073709551616"] {
            assert!(
                linux_identity_from_records(42, BOOT_A, &stat_record(42, b"x", ticks)).is_none()
            );
        }
        for boot in [
            b"".as_slice(),
            b"not-a-boot-id",
            b"12345678-1234-1234-1234-123456789abg",
        ] {
            assert!(linux_identity_from_records(42, boot, &first).is_none());
        }
        for stat in [b"".as_slice(), b"42 (broken", b"42 (x) S 0", b"42 (x)S 0"] {
            assert!(linux_identity_from_records(42, BOOT_A, stat).is_none());
        }
    }

    #[tokio::test]
    async fn linux_identity_reads_are_bounded_and_fail_closed() {
        let temp = tempdir().unwrap();
        let boot = temp.path().join("sys/kernel/random/boot_id");
        let stat = temp.path().join("42/stat");
        fs::create_dir_all(boot.parent().unwrap()).unwrap();
        fs::create_dir_all(stat.parent().unwrap()).unwrap();
        assert!(linux_start_fingerprint(temp.path(), 42).await.is_none());
        fs::write(&boot, BOOT_A).unwrap();
        assert!(linux_start_fingerprint(temp.path(), 42).await.is_none());
        fs::write(&stat, stat_record(42, b"x", "18446744073709551615")).unwrap();
        assert_eq!(
            linux_start_fingerprint(temp.path(), 42)
                .await
                .unwrap()
                .len(),
            63
        );
        fs::write(&stat, vec![b'x'; MAX_PROC_STAT_BYTES + 1]).unwrap();
        assert!(linux_start_fingerprint(temp.path(), 42).await.is_none());
        fs::write(&stat, stat_record(42, b"x", "1")).unwrap();
        fs::write(&boot, [BOOT_A, b"\n"].concat()).unwrap();
        assert!(linux_start_fingerprint(temp.path(), 42).await.is_none());
        fs::remove_file(&boot).unwrap();
        assert!(linux_start_fingerprint(temp.path(), 42).await.is_none());
        assert!(linux_start_fingerprint(temp.path(), 0).await.is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_start_fingerprint_uses_boot_identity_and_kernel_ticks() {
        let pid = std::process::id();
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        // comm can itself contain spaces and ')'; fields after its final ')' start at 3.
        let ticks: u64 = stat
            .rsplit_once(')')
            .unwrap()
            .1
            .split_ascii_whitespace()
            .nth(19)
            .unwrap()
            .parse()
            .unwrap();
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let expected = format!("linux:{}:{ticks}", boot.trim());
        let actual = start_fingerprint(pid, 64).await.unwrap();
        assert!(
            actual == expected,
            "identity must use boot ID and kernel ticks, not wall time"
        );
        assert!(start_fingerprint(u32::MAX, 64).await.is_none());
        assert!(start_fingerprint(0, 64).await.is_none());
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
