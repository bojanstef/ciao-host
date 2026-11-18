//! Signal/descriptor setup for the single-threaded hidden image helper, never the daemon.
use nix::libc;

/// Refuse auto-reaping parents: exclusive wait ownership requires a retained zombie until wait.
/// Does not change Tokio's SIGCHLD handler or any daemon signal state.
pub fn can_reap_probe_children() -> bool {
    // SAFETY: initialized output structure, null new action leaves process state unchanged.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: null new mask queries only this thread's signal mask.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    (unsafe {
        libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) == 0
            && libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) == 0
            && libc::sigismember(&mask, libc::SIGCHLD) == 0
    }) && action.sa_sigaction != libc::SIG_IGN
        && action.sa_flags & libc::SA_NOCLDWAIT == 0
}

/// Must run only in the dedicated helper. Timers survive same-process exec, but a vendor can
/// cancel/block them; this is the ordinary trusted-version-probe lifetime contract, not custody.
pub fn reset_probe_alarm(seconds: u32) -> Option<()> {
    if seconds == 0 || seconds > 30 {
        return None;
    }
    // SAFETY: initialized structures and valid standard signal numbers. Only the helper calls.
    unsafe {
        let mut empty: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&mut empty) != 0
            || libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0
        {
            return None;
        }
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        action.sa_mask = empty;
        for signal in 1..32 {
            if signal != libc::SIGKILL
                && signal != libc::SIGSTOP
                && libc::sigaction(signal, &action, std::ptr::null_mut()) != 0
            {
                return None;
            }
        }
        libc::alarm(seconds);
    }
    Some(())
}

/// Arm before any blocking work, then close inherited daemon/auth/control descriptors.
pub fn prepare_probe_helper(seconds: u32) -> Option<()> {
    reset_probe_alarm(seconds)?;
    #[cfg(target_os = "macos")]
    {
        let mut entries = [[0i32; 2]; 4096];
        let capacity = std::mem::size_of_val(&entries) as i32;
        // SAFETY: PROC_PIDLISTFDS writes {int32 fd,uint32 type} entries into the bounded array.
        let size = unsafe {
            libc::proc_pidinfo(
                std::process::id() as i32,
                1,
                0,
                entries.as_mut_ptr().cast(),
                capacity,
            )
        };
        if size <= 0 || size >= capacity || size % 8 != 0 {
            return None;
        }
        for entry in entries.iter().take(size as usize / 8) {
            if entry[0] >= 3 {
                // SAFETY: single threaded and before opening any owned helper descriptor.
                unsafe {
                    libc::close(entry[0]);
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        // Linux >=5.9. Refuse ENOSYS rather than silently leak inherited descriptors.
        // SAFETY: close_range affects only this dedicated helper's descriptors >=3.
        if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } != 0 {
            return None;
        }
    }
    Some(())
}
