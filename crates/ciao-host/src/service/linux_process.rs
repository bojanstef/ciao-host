//! Recover pre-lock daemons even after a pathname has been unlinked. Linux keeps
//! the bound name on the listening socket object in /proc/net/unix until close.
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    os::{
        fd::OwnedFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
    process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal},
};

use crate::storage::CiaoPaths;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum Listener {
    Control,
    Agent,
}

fn parse_unix_table_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
    // Kernel `unix_seq_show` prints the inode column with `%5lu`, which inserts leading spaces
    // for inodes < 10000. Consume runs of spaces between the 7 fixed columns while keeping spaces
    // inside the trailing socket pathname intact.
    let mut rest = line;
    let mut columns = [&b""[..]; 7];
    for slot in &mut columns {
        while rest.first() == Some(&b' ') {
            rest = &rest[1..];
        }
        let end = rest.iter().position(|b| *b == b' ')?;
        *slot = &rest[..end];
        rest = &rest[end..];
    }
    while rest.first() == Some(&b' ') {
        rest = &rest[1..];
    }
    if rest.is_empty() {
        return None;
    }
    if columns[3] == b"00010000" && columns[4] == b"0001" && columns[5] == b"01" {
        Some((columns[6], rest))
    } else {
        None
    }
}

fn listener_inodes(paths: &CiaoPaths) -> Result<HashMap<Vec<u8>, Listener>> {
    let table = fs::read("/proc/net/unix").context("inspect Unix listeners")?;
    let mut inodes = HashMap::new();
    for line in table.split(|b| *b == b'\n') {
        if let Some((inode, path)) = parse_unix_table_line(line) {
            let kind = if path == paths.socket_file.as_os_str().as_bytes() {
                Listener::Control
            } else if path == paths.agent_socket_file.as_os_str().as_bytes() {
                Listener::Agent
            } else {
                continue;
            };
            inodes.insert([b"socket:[", inode, b"]"].concat(), kind);
        }
    }
    Ok(inodes)
}

fn daemon_invocation(dir: &Path) -> bool {
    if !dir
        .metadata()
        .is_ok_and(|m| m.uid() == nix::unistd::Uid::effective().as_raw())
    {
        return false;
    }
    let Ok(argv) = fs::read(dir.join("cmdline")) else {
        return false;
    };
    argv.splitn(2, |b| *b == 0).nth(1) == Some(b"daemon\0")
}

fn same_run_directory(dir: &Path, run: &Path, ours: &fs::Metadata) -> bool {
    let Ok(relative) = run.strip_prefix("/") else {
        return false;
    };
    dir.join("root")
        .join(relative)
        .metadata()
        .is_ok_and(|other| other.dev() == ours.dev() && other.ino() == ours.ino())
}

pub(super) fn holders(paths: &CiaoPaths) -> Result<Vec<OwnedFd>> {
    let mut wanted = listener_inodes(paths)?;
    let mut holders = Vec::new();
    if wanted.is_empty() {
        return Ok(holders);
    }
    let our_dir = paths.run_dir.metadata()?;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|v| v.parse::<i32>().ok())
            .and_then(Pid::from_raw)
        else {
            continue;
        };
        let dir = entry.path();
        if !daemon_invocation(&dir) {
            continue;
        }
        // Pin before reading the fd table. If a PID is recycled during inspection,
        // this handle can only address the original, already exited process.
        let handle = match pidfd_open(pid, PidfdFlags::empty()) {
            Ok(handle) => handle,
            Err(Errno::SRCH) => continue,
            Err(err) => return Err(err).context("identify daemon process"),
        };
        if !same_run_directory(&dir, &paths.run_dir, &our_dir) || !daemon_invocation(&dir) {
            continue;
        }
        let mut matched = HashSet::new();
        if let Ok(fds) = fs::read_dir(dir.join("fd")) {
            for fd in fds.flatten() {
                if let Ok(link) = fs::read_link(fd.path())
                    && let Some(kind) = wanted.remove(link.as_os_str().as_bytes())
                {
                    matched.insert(kind);
                }
            }
        }
        if matched.len() == 1 {
            bail!("only one Ciao listener could be attributed to this process; leaving it running");
        }
        if matched.len() == 2 {
            holders.push(handle);
        }
    }
    if !wanted.is_empty()
        && listener_inodes(paths)?
            .keys()
            .any(|inode| wanted.contains_key(inode))
    {
        bail!("could not verify the process holding a Ciao listener; leaving it running");
    }
    Ok(holders)
}

pub(super) fn stop(paths: &CiaoPaths) -> Result<()> {
    stop_holders(holders(paths)?)
}

pub(super) fn stop_holders(handles: Vec<OwnedFd>) -> Result<()> {
    for handle in &handles {
        signal(handle, Signal::TERM)?;
    }
    let graceful_deadline = Instant::now() + Duration::from_secs(20);
    let mut unresponsive = Vec::new();
    for handle in handles {
        if !exited_by(&handle, graceful_deadline)? {
            // As with KillMode=process, escalation addresses only the identified
            // main process. Descendant terminal servers keep running.
            signal(&handle, Signal::KILL)?;
            unresponsive.push(handle);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    for handle in unresponsive {
        if !exited_by(&handle, deadline)? {
            bail!("the kernel has not finished terminating the previous Ciao daemon");
        }
    }
    Ok(())
}

fn signal(handle: &OwnedFd, signal: Signal) -> Result<()> {
    match pidfd_send_signal(handle, signal) {
        Ok(()) | Err(Errno::SRCH) => Ok(()),
        Err(err) => Err(err).context("signal the previous Ciao daemon"),
    }
}

fn exited_by(handle: &OwnedFd, deadline: Instant) -> Result<bool> {
    let mut fds = [PollFd::new(handle, PollFlags::IN)];
    loop {
        let timeout = Timespec::try_from(deadline.saturating_duration_since(Instant::now()))?;
        match poll(&mut fds, Some(&timeout)) {
            Ok(ready) => return Ok(ready > 0),
            Err(Errno::INTR) => continue,
            Err(err) => return Err(io::Error::from(err)).context("wait for previous daemon"),
        }
    }
}
