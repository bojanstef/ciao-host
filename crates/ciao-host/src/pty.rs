use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{ffi::OsStrExt as _, fs::OpenOptionsExt as _},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    sys::signal::{Signal, killpg},
    unistd::{AccessFlags, Pid, Uid, User, access, getpgid, getsid, tcgetpgrp},
};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use thiserror::Error;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
    time::timeout,
};

use crate::host_protocol::{
    Dimensions, HOST_PENDING_INPUT_BYTES, HOST_PENDING_OUTPUT_BYTES, MAX_DATA_PAYLOAD,
};

const PTY_READ_BYTES: usize = 16 * 1024;
const INPUT_ITEMS: usize = HOST_PENDING_INPUT_BYTES / MAX_DATA_PAYLOAD;
const OUTPUT_ITEMS: usize = HOST_PENDING_OUTPUT_BYTES / PTY_READ_BYTES;
const RESIZE_MIN_INTERVAL: Duration = Duration::from_millis(50);
const SIGNAL_WAIT: Duration = Duration::from_secs(1);
const KILL_WAIT: Duration = Duration::from_secs(2);
const TASK_STOP_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_ENV_VALUE_BYTES: usize = 32 * 1024;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PtyError {
    #[error("the account login shell is unavailable")]
    ShellUnavailable,
    #[error("the PTY could not be opened")]
    OpenFailed,
    #[error("the shell could not be spawned")]
    SpawnFailed,
    #[error("the PTY input queue is closed")]
    InputClosed,
    #[error("the PTY input frame is invalid")]
    InvalidInput,
    #[error("the PTY resize failed")]
    ResizeFailed,
    #[error("the PTY child wait failed")]
    WaitFailed,
    #[error("the PTY cleanup did not finish")]
    CleanupFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PtyExit {
    Exited(u32),
    Signaled(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleanupReason {
    ExplicitClose,
    StreamEnded,
    ConnectionLost,
    BridgeFailure,
    ServerShutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueueHighWaterMarks {
    pub input_bytes: usize,
    pub output_bytes: usize,
}

pub(crate) struct PtyOutput {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

impl PtyOutput {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone)]
pub(crate) struct PtyExitWatcher {
    receiver: watch::Receiver<Option<Result<PtyExit, PtyError>>>,
}

impl PtyExitWatcher {
    pub(crate) async fn wait(&mut self) -> Result<PtyExit, PtyError> {
        loop {
            if let Some(result) = self.receiver.borrow().clone() {
                return result;
            }
            self.receiver
                .changed()
                .await
                .map_err(|_| PtyError::WaitFailed)?;
        }
    }
}

struct InputChunk {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

enum MasterCommand {
    Resize(Dimensions, oneshot::Sender<Result<(), PtyError>>),
    Close(oneshot::Sender<()>),
}

struct SpawnedPty {
    master: Box<dyn portable_pty::MasterPty + Send>,
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    killer: Box<dyn portable_pty::ChildKiller + Send + Sync>,
    child_pid: Pid,
    shell_session_id: Pid,
    tty: Option<File>,
    tty_name: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub(crate) struct AccountRecord {
    pub(crate) name: String,
    pub(crate) home: PathBuf,
    pub(crate) shell: PathBuf,
    used_fallback_shell: bool,
}

trait CommandFactory: Send + Sync {
    fn build(&self, account: &AccountRecord) -> Result<CommandBuilder, PtyError>;
}

struct LoginShellCommandFactory;

impl CommandFactory for LoginShellCommandFactory {
    fn build(&self, account: &AccountRecord) -> Result<CommandBuilder, PtyError> {
        let mut command = CommandBuilder::new_default_prog();
        configure_clean_environment(&mut command, account);
        Ok(command)
    }
}

/// Runs a fixed, pre-validated provider argv (Spec 003 §4.4) as the PTY child with the same
/// cleaned environment as the login shell. This is the only production path besides the login
/// shell, and its argv is constructed exclusively by `workspace::target_command`.
struct FixedArgvCommandFactory {
    program: PathBuf,
    args: Vec<std::ffi::OsString>,
}

impl CommandFactory for FixedArgvCommandFactory {
    fn build(&self, account: &AccountRecord) -> Result<CommandBuilder, PtyError> {
        let mut command = CommandBuilder::new(&self.program);
        command.args(&self.args);
        configure_clean_environment(&mut command, account);
        Ok(command)
    }
}

pub(crate) struct PtySession {
    terminal_id: String,
    child_pid: Pid,
    shell_session_id: Pid,
    /// The client side of the terminal, reopened by name so cleanup can ask which process group
    /// is in the foreground. Shared and droppable because it has to be closed the moment the
    /// child exits: a master reports end-of-file only once every client descriptor is gone, so
    /// holding this past the child's death keeps the reader alive and the session is never
    /// reported as finished.
    tty: Arc<StdMutex<Option<File>>>,
    tty_name: Option<PathBuf>,
    input_sender: Option<mpsc::Sender<InputChunk>>,
    input_semaphore: Arc<Semaphore>,
    output_receiver: mpsc::Receiver<PtyOutput>,
    output_semaphore: Arc<Semaphore>,
    resize_sender: Option<watch::Sender<Dimensions>>,
    master_sender: Option<mpsc::Sender<MasterCommand>>,
    exit_receiver: watch::Receiver<Option<Result<PtyExit, PtyError>>>,
    killer: Arc<StdMutex<Box<dyn portable_pty::ChildKiller + Send + Sync>>>,
    cancelled: Arc<AtomicBool>,
    input_high_water: Arc<AtomicUsize>,
    output_high_water: Arc<AtomicUsize>,
    writer_task: Option<JoinHandle<()>>,
    reader_task: Option<JoinHandle<()>>,
    master_task: Option<JoinHandle<()>>,
    wait_task: Option<JoinHandle<()>>,
    resize_task: Option<JoinHandle<()>>,
    cleaned: bool,
    /// Kill the child outright at cleanup instead of walking the HUP/TERM ladder. Set for
    /// herdr attach clients: they are pure viewers of server-side state, and a graceful
    /// teardown gives the dying client a window in which it misreads teardown as keystrokes
    /// and types them into the focused pane — observed as Ctrl+J/Ctrl+D arriving at a
    /// claude composer milliseconds before the client's disconnect (the stray-newline bug).
    viewer_cleanup: bool,
}

impl PtySession {
    pub(crate) async fn spawn_login_shell(dimensions: Dimensions) -> Result<Self, PtyError> {
        Self::spawn_with_factory(dimensions, Arc::new(LoginShellCommandFactory)).await
    }

    pub(crate) async fn spawn_fixed_argv(
        dimensions: Dimensions,
        program: PathBuf,
        args: Vec<std::ffi::OsString>,
    ) -> Result<Self, PtyError> {
        Self::spawn_with_factory(
            dimensions,
            Arc::new(FixedArgvCommandFactory { program, args }),
        )
        .await
    }

    async fn spawn_with_factory(
        dimensions: Dimensions,
        command_factory: Arc<dyn CommandFactory>,
    ) -> Result<Self, PtyError> {
        dimensions.validate().map_err(|_| PtyError::OpenFailed)?;
        let spawned = tokio::task::spawn_blocking(move || {
            spawn_pty_blocking(dimensions, command_factory.as_ref())
        })
        .await
        .map_err(|_| PtyError::SpawnFailed)??;

        let SpawnedPty {
            master,
            mut reader,
            mut writer,
            child,
            killer,
            child_pid,
            shell_session_id,
            tty,
            tty_name,
        } = spawned;

        let cancelled = Arc::new(AtomicBool::new(false));
        let input_semaphore = Arc::new(Semaphore::new(HOST_PENDING_INPUT_BYTES));
        let output_semaphore = Arc::new(Semaphore::new(HOST_PENDING_OUTPUT_BYTES));
        let input_high_water = Arc::new(AtomicUsize::new(0));
        let output_high_water = Arc::new(AtomicUsize::new(0));

        let (input_sender, mut input_receiver) = mpsc::channel::<InputChunk>(INPUT_ITEMS);
        let writer_cancelled = cancelled.clone();
        let writer_task = tokio::task::spawn_blocking(move || {
            while let Some(chunk) = input_receiver.blocking_recv() {
                if writer_cancelled.load(Ordering::Acquire) {
                    break;
                }
                if writer.write_all(&chunk.bytes).is_err() || writer.flush().is_err() {
                    break;
                }
            }
        });

        let (output_sender, output_receiver) = mpsc::channel::<PtyOutput>(OUTPUT_ITEMS);
        let output_queue = output_semaphore.clone();
        let output_high_water_task = output_high_water.clone();
        let reader_cancelled = cancelled.clone();
        let runtime = tokio::runtime::Handle::current();
        let reader_task = tokio::task::spawn_blocking(move || {
            let mut buffer = [0_u8; PTY_READ_BYTES];
            loop {
                if reader_cancelled.load(Ordering::Acquire) {
                    break;
                }
                let count = match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    // macOS commonly reports EIO when the PTY slave has closed. Treat all
                    // terminal-reader failures as categorical bridge termination; no bytes or
                    // OS-provided path text is propagated into diagnostics.
                    Err(_) => break,
                };
                let permit = match runtime.block_on(
                    output_queue
                        .clone()
                        .acquire_many_owned(u32::try_from(count).expect("PTY chunk is <= 16 KiB")),
                ) {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                update_high_water(
                    &output_high_water_task,
                    HOST_PENDING_OUTPUT_BYTES - output_queue.available_permits(),
                );
                if output_sender
                    .blocking_send(PtyOutput {
                        bytes: buffer[..count].to_vec(),
                        _permit: permit,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });

        let (master_sender, mut master_receiver) = mpsc::channel::<MasterCommand>(1);
        let master_task = tokio::task::spawn_blocking(move || {
            while let Some(command) = master_receiver.blocking_recv() {
                match command {
                    MasterCommand::Resize(dimensions, acknowledgement) => {
                        let result = master
                            .resize(to_pty_size(dimensions))
                            .map_err(|_| PtyError::ResizeFailed);
                        let _ = acknowledgement.send(result);
                    }
                    MasterCommand::Close(acknowledgement) => {
                        drop(master);
                        let _ = acknowledgement.send(());
                        break;
                    }
                }
            }
        });

        let (resize_sender, mut resize_receiver) = watch::channel(dimensions);
        resize_receiver.borrow_and_update();
        let resize_master = master_sender.clone();
        let resize_cancelled = cancelled.clone();
        let resize_task = tokio::spawn(async move {
            let mut last_applied = Instant::now()
                .checked_sub(RESIZE_MIN_INTERVAL)
                .unwrap_or_else(Instant::now);
            loop {
                if resize_receiver.changed().await.is_err()
                    || resize_cancelled.load(Ordering::Acquire)
                {
                    break;
                }
                let elapsed = last_applied.elapsed();
                if elapsed < RESIZE_MIN_INTERVAL {
                    tokio::time::sleep(RESIZE_MIN_INTERVAL - elapsed).await;
                }
                let newest = *resize_receiver.borrow_and_update();
                let (acknowledgement, result) = oneshot::channel();
                if resize_master
                    .send(MasterCommand::Resize(newest, acknowledgement))
                    .await
                    .is_err()
                {
                    break;
                }
                if result.await.is_err() {
                    break;
                }
                last_applied = Instant::now();
            }
        });

        let tty = Arc::new(StdMutex::new(tty));
        let (exit_sender, exit_receiver) = watch::channel(None);
        let wait_exit_tty = tty.clone();
        let wait_task = tokio::task::spawn_blocking(move || {
            let mut child = child;
            let result = child
                .wait()
                .map(|status| map_exit_status(&status))
                .map_err(|_| PtyError::WaitFailed);
            // Closed here rather than in cleanup, because cleanup does not run until the session
            // is reported finished and that report waits on the reader draining. The child was
            // the only other holder of a client descriptor, so dropping ours is what lets the
            // master reach end-of-file at all. Linux enforces this strictly; macOS is laxer,
            // which is why holding it went unnoticed there.
            if let Ok(mut tty) = wait_exit_tty.lock() {
                tty.take();
            }
            let _ = exit_sender.send(Some(result));
        });

        Ok(Self {
            terminal_id: crate::protocol::base64url(&rand::random::<[u8; 16]>()),
            child_pid,
            shell_session_id,
            tty,
            tty_name,
            input_sender: Some(input_sender),
            input_semaphore,
            output_receiver,
            output_semaphore,
            resize_sender: Some(resize_sender),
            master_sender: Some(master_sender),
            exit_receiver,
            killer: Arc::new(StdMutex::new(killer)),
            cancelled,
            input_high_water,
            output_high_water,
            writer_task: Some(writer_task),
            reader_task: Some(reader_task),
            master_task: Some(master_task),
            wait_task: Some(wait_task),
            resize_task: Some(resize_task),
            cleaned: false,
            viewer_cleanup: false,
        })
    }

    pub(crate) fn terminal_id(&self) -> &str {
        &self.terminal_id
    }

    pub(crate) fn mark_viewer_cleanup(&mut self) {
        self.viewer_cleanup = true;
    }

    /// Trusted local PTY identity used to detach exactly Ciao's tmux client. It is never
    /// transported or logged.
    pub(crate) fn client_tty(&self) -> Option<&Path> {
        self.tty_name.as_deref()
    }

    /// Process groups this session may signal. The terminal is closed as soon as the child
    /// exits, so after that point there is no foreground group left to ask about and only the
    /// child's own group remains.
    fn owned_groups(&self) -> Vec<Pid> {
        let tty = self.tty.lock().ok();
        owned_process_groups(
            self.child_pid,
            self.shell_session_id,
            tty.as_ref().and_then(|tty| tty.as_ref()),
        )
    }

    pub(crate) fn exit_watcher(&self) -> PtyExitWatcher {
        PtyExitWatcher {
            receiver: self.exit_receiver.clone(),
        }
    }

    pub(crate) async fn send_input(&self, bytes: Vec<u8>) -> Result<(), PtyError> {
        if bytes.is_empty() || bytes.len() > MAX_DATA_PAYLOAD {
            return Err(PtyError::InvalidInput);
        }
        let sender = self.input_sender.as_ref().ok_or(PtyError::InputClosed)?;
        let count = u32::try_from(bytes.len()).map_err(|_| PtyError::InvalidInput)?;
        let permit = self
            .input_semaphore
            .clone()
            .acquire_many_owned(count)
            .await
            .map_err(|_| PtyError::InputClosed)?;
        update_high_water(
            &self.input_high_water,
            HOST_PENDING_INPUT_BYTES - self.input_semaphore.available_permits(),
        );
        sender
            .send(InputChunk {
                bytes,
                _permit: permit,
            })
            .await
            .map_err(|_| PtyError::InputClosed)
    }

    pub(crate) async fn next_output(&mut self) -> Option<PtyOutput> {
        self.output_receiver.recv().await
    }

    pub(crate) fn request_resize(&self, dimensions: Dimensions) -> Result<(), PtyError> {
        dimensions.validate().map_err(|_| PtyError::ResizeFailed)?;
        let sender = self.resize_sender.as_ref().ok_or(PtyError::ResizeFailed)?;
        // Resizing to the size the PTY already has is not free: the ioctl still delivers
        // SIGWINCH to the foreground process group, and a TUI that redraws its composer on
        // that signal can leave a blank line behind. The app replays its retained dimensions
        // every time it installs a resize mailbox — once per foreground — so without this
        // guard every app open spends one redundant signal on a size that did not change.
        // `send_replace` marks the watch changed unconditionally; this does not.
        sender.send_if_modified(|current| {
            if *current == dimensions {
                return false;
            }
            *current = dimensions;
            true
        });
        Ok(())
    }

    pub(crate) fn queue_high_water_marks(&self) -> QueueHighWaterMarks {
        QueueHighWaterMarks {
            input_bytes: self.input_high_water.load(Ordering::Relaxed),
            output_bytes: self.output_high_water.load(Ordering::Relaxed),
        }
    }

    pub(crate) async fn finish_normal(&mut self) -> Result<PtyExit, PtyError> {
        let result = wait_for_exit(&mut self.exit_receiver).await;
        self.stop_bridges().await?;
        result
    }

    pub(crate) async fn cleanup(
        &mut self,
        _reason: CleanupReason,
    ) -> Result<Option<PtyExit>, PtyError> {
        if self.cleaned {
            return current_exit(&self.exit_receiver);
        }
        self.cleaned = true;

        let groups = self.owned_groups();
        if self.viewer_cleanup {
            // Kill before any handle closes so the viewer's teardown never runs against a
            // collapsing stdin — the window in which it types phantom keys into the session.
            signal_groups(&groups, Signal::SIGKILL);
            if let Ok(mut killer) = self.killer.lock() {
                let _ = killer.kill();
            }
        }
        self.stop_accepting_and_close_handles().await;

        if let Some(exit) = current_exit(&self.exit_receiver)? {
            self.finish_tasks().await?;
            return Ok(Some(exit));
        }

        signal_groups(&groups, Signal::SIGHUP);
        if let Some(exit) = wait_for_exit_timeout(&mut self.exit_receiver, SIGNAL_WAIT).await? {
            self.finish_tasks().await?;
            return Ok(Some(exit));
        }

        signal_groups(&groups, Signal::SIGTERM);
        if let Some(exit) = wait_for_exit_timeout(&mut self.exit_receiver, SIGNAL_WAIT).await? {
            self.finish_tasks().await?;
            return Ok(Some(exit));
        }

        signal_groups(&groups, Signal::SIGKILL);
        if let Ok(mut killer) = self.killer.lock() {
            let _ = killer.kill();
        }
        let exit = wait_for_exit_timeout(&mut self.exit_receiver, KILL_WAIT).await?;
        self.finish_tasks().await?;
        exit.ok_or(PtyError::CleanupFailed).map(Some)
    }

    async fn stop_bridges(&mut self) -> Result<(), PtyError> {
        if self.cleaned {
            return Ok(());
        }
        self.cleaned = true;
        self.stop_accepting_and_close_handles().await;
        self.finish_tasks().await
    }

    async fn stop_accepting_and_close_handles(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.input_sender.take();
        self.input_semaphore.close();
        self.resize_sender.take();
        if let Some(task) = self.resize_task.take() {
            task.abort();
            let _ = task.await;
        }

        self.output_receiver.close();
        while self.output_receiver.try_recv().is_ok() {}
        self.output_semaphore.close();

        if let Some(sender) = self.master_sender.take() {
            let (acknowledgement, result) = oneshot::channel();
            if sender
                .send(MasterCommand::Close(acknowledgement))
                .await
                .is_ok()
            {
                let _ = timeout(TASK_STOP_TIMEOUT, result).await;
            }
        }
    }

    async fn finish_tasks(&mut self) -> Result<(), PtyError> {
        let mut failed = false;
        for task in [
            &mut self.writer_task,
            &mut self.reader_task,
            &mut self.master_task,
            &mut self.wait_task,
        ] {
            if let Some(handle) = task.take()
                && timeout(TASK_STOP_TIMEOUT, handle).await.is_err()
            {
                failed = true;
            }
        }
        if failed {
            Err(PtyError::CleanupFailed)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    fn child_pid(&self) -> Pid {
        self.child_pid
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        self.cancelled.store(true, Ordering::Release);
        self.input_sender.take();
        self.input_semaphore.close();
        self.output_receiver.close();
        self.output_semaphore.close();
        self.resize_sender.take();
        if let Some(sender) = self.master_sender.take() {
            let (acknowledgement, _) = oneshot::channel();
            let _ = sender.try_send(MasterCommand::Close(acknowledgement));
        }
        signal_groups(&self.owned_groups(), Signal::SIGHUP);
        if let Ok(mut killer) = self.killer.lock() {
            let _ = killer.kill();
        }
    }
}

fn spawn_pty_blocking(
    dimensions: Dimensions,
    command_factory: &dyn CommandFactory,
) -> Result<SpawnedPty, PtyError> {
    let account = resolve_account()?;
    if account.used_fallback_shell {
        tracing::warn!("account login shell unavailable; using the safe fallback shell");
    }
    let command = command_factory.build(&account)?;
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(to_pty_size(dimensions))
        .map_err(|_| PtyError::OpenFailed)?;
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|_| PtyError::OpenFailed)?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|_| PtyError::OpenFailed)?;
    let tty_name = pair.master.tty_name();
    let tty = tty_name.as_deref().and_then(open_tty);
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|_| PtyError::SpawnFailed)?;
    drop(pair.slave);
    let identity = (|| {
        let child_pid_raw = child.process_id().ok_or(PtyError::SpawnFailed)?;
        let child_pid_raw = i32::try_from(child_pid_raw).map_err(|_| PtyError::SpawnFailed)?;
        if child_pid_raw <= 1 {
            return Err(PtyError::SpawnFailed);
        }
        let child_pid = Pid::from_raw(child_pid_raw);
        let shell_session_id = getsid(Some(child_pid)).map_err(|_| PtyError::SpawnFailed)?;
        if shell_session_id != child_pid {
            return Err(PtyError::SpawnFailed);
        }
        let leader = pair.master.process_group_leader();
        if leader.is_some_and(|leader| leader != child_pid_raw) {
            return Err(PtyError::SpawnFailed);
        }
        Ok((child_pid, shell_session_id))
    })();
    let (child_pid, shell_session_id) = match identity {
        Ok(identity) => identity,
        Err(error) => {
            let mut killer = child.clone_killer();
            let _ = killer.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let killer = child.clone_killer();
    Ok(SpawnedPty {
        master: pair.master,
        reader,
        writer,
        child,
        killer,
        child_pid,
        shell_session_id,
        tty,
        tty_name,
    })
}

pub(crate) fn resolve_account() -> Result<AccountRecord, PtyError> {
    let user = User::from_uid(Uid::effective())
        .map_err(|_| PtyError::ShellUnavailable)?
        .ok_or(PtyError::ShellUnavailable)?;
    if !user.dir.is_absolute() || !user.dir.is_dir() || user.name.is_empty() {
        return Err(PtyError::ShellUnavailable);
    }
    let shell_is_valid = is_absolute_executable(&user.shell);
    let shell = if shell_is_valid {
        user.shell
    } else {
        let fallback = PathBuf::from("/bin/sh");
        if !is_absolute_executable(&fallback) {
            return Err(PtyError::ShellUnavailable);
        }
        fallback
    };
    Ok(AccountRecord {
        name: user.name,
        home: user.dir,
        shell,
        used_fallback_shell: !shell_is_valid,
    })
}

pub(crate) fn is_absolute_executable(path: &Path) -> bool {
    path.is_absolute() && path.is_file() && access(path, AccessFlags::X_OK).is_ok()
}

/// Applies the same cleaned environment policy as the PTY broker to a non-PTY provider
/// invocation (Spec 003 §5.2): fixed HOME/USER/LOGNAME/SHELL/TERM/COLORTERM values plus the
/// Phase 1 inherit allowlist; nothing else crosses into the child.
pub(crate) fn apply_clean_process_environment(
    command: &mut tokio::process::Command,
) -> Result<(), PtyError> {
    let account = resolve_account()?;
    command.env_clear();
    command.current_dir(&account.home);
    command.env("HOME", &account.home);
    command.env("USER", &account.name);
    command.env("LOGNAME", &account.name);
    command.env("SHELL", &account.shell);
    command.env("TERM", "xterm-256color");
    command.env("COLORTERM", "truecolor");
    for (key, value) in std::env::vars_os() {
        if inherited_environment_key(&key) && valid_environment_value(&key, &value) {
            command.env(key, value);
        }
    }
    Ok(())
}

fn configure_clean_environment(command: &mut CommandBuilder, account: &AccountRecord) {
    command.env_clear();
    command.cwd(&account.home);
    command.env("HOME", &account.home);
    command.env("USER", &account.name);
    command.env("LOGNAME", &account.name);
    command.env("SHELL", &account.shell);
    command.env("TERM", "xterm-256color");
    command.env("COLORTERM", "truecolor");

    for (key, value) in std::env::vars_os() {
        if inherited_environment_key(&key) && valid_environment_value(&key, &value) {
            command.env(key, value);
        }
    }
}

fn inherited_environment_key(key: &OsStr) -> bool {
    matches!(
        key.to_str(),
        Some("PATH" | "TMPDIR" | "LANG" | "SSH_AUTH_SOCK")
    ) || key
        .to_str()
        .is_some_and(|key| key.starts_with("LC_") && key.len() <= 64)
}

fn valid_environment_value(key: &OsStr, value: &OsStr) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_ENV_VALUE_BYTES {
        return false;
    }
    match key.to_str() {
        Some("TMPDIR" | "SSH_AUTH_SOCK") => Path::new(value).is_absolute(),
        _ => true,
    }
}

fn to_pty_size(dimensions: Dimensions) -> PtySize {
    PtySize {
        rows: dimensions.rows,
        cols: dimensions.cols,
        pixel_width: dimensions.pixel_width,
        pixel_height: dimensions.pixel_height,
    }
}

fn open_tty(path: &Path) -> Option<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NOCTTY | nix::libc::O_CLOEXEC)
        .open(path)
        .ok()
}

fn owned_process_groups(child_pid: Pid, shell_session_id: Pid, tty: Option<&File>) -> Vec<Pid> {
    let mut groups = BTreeSet::new();
    if let Ok(shell_group) = getpgid(Some(child_pid))
        && valid_owned_group(shell_group, shell_session_id)
    {
        groups.insert(shell_group.as_raw());
    }
    if let Some(tty) = tty
        && let Ok(foreground_group) = tcgetpgrp(tty)
        && valid_owned_group(foreground_group, shell_session_id)
    {
        groups.insert(foreground_group.as_raw());
    }
    groups.into_iter().map(Pid::from_raw).collect()
}

fn valid_owned_group(group: Pid, shell_session_id: Pid) -> bool {
    group.as_raw() > 1
        && shell_session_id.as_raw() > 1
        && getsid(Some(group)).is_ok_and(|session| session == shell_session_id)
}

fn signal_groups(groups: &[Pid], signal: Signal) {
    for group in groups {
        match killpg(*group, signal) {
            Ok(()) | Err(Errno::ESRCH) => {}
            Err(_) => {
                // Continue through the cleanup escalation. Diagnostics intentionally remain
                // categorical and never include process arguments or environment values.
                tracing::warn!(stage = ?signal, "PTY process-group signal failed");
            }
        }
    }
}

fn map_exit_status(status: &portable_pty::ExitStatus) -> PtyExit {
    match status.signal() {
        Some(signal) => PtyExit::Signaled(normalize_signal_name(signal)),
        None => PtyExit::Exited(status.exit_code()),
    }
}

fn normalize_signal_name(value: &str) -> String {
    let lowercase = value.to_ascii_lowercase();
    for (needle, name) in [
        ("hangup", "SIGHUP"),
        ("interrupt", "SIGINT"),
        ("quit", "SIGQUIT"),
        ("killed", "SIGKILL"),
        ("terminated", "SIGTERM"),
        ("broken pipe", "SIGPIPE"),
    ] {
        if lowercase.contains(needle) {
            return name.into();
        }
    }
    let sanitized: String = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
        .take(32)
        .collect();
    if sanitized.is_empty() {
        "SIGNAL".into()
    } else {
        sanitized
    }
}

fn current_exit(
    receiver: &watch::Receiver<Option<Result<PtyExit, PtyError>>>,
) -> Result<Option<PtyExit>, PtyError> {
    match receiver.borrow().clone() {
        Some(Ok(exit)) => Ok(Some(exit)),
        Some(Err(error)) => Err(error),
        None => Ok(None),
    }
}

async fn wait_for_exit(
    receiver: &mut watch::Receiver<Option<Result<PtyExit, PtyError>>>,
) -> Result<PtyExit, PtyError> {
    loop {
        if let Some(exit) = current_exit(receiver)? {
            return Ok(exit);
        }
        receiver.changed().await.map_err(|_| PtyError::WaitFailed)?;
    }
}

async fn wait_for_exit_timeout(
    receiver: &mut watch::Receiver<Option<Result<PtyExit, PtyError>>>,
    duration: Duration,
) -> Result<Option<PtyExit>, PtyError> {
    if let Some(exit) = current_exit(receiver)? {
        return Ok(Some(exit));
    }
    match timeout(duration, wait_for_exit(receiver)).await {
        Ok(result) => result.map(Some),
        Err(_) => Ok(None),
    }
}

fn update_high_water(mark: &AtomicUsize, value: usize) {
    let _ = mark.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        (value > current).then_some(value)
    });
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, process::Command};

    use super::*;

    #[derive(Clone)]
    struct TestCommandFactory {
        program: PathBuf,
        args: Vec<OsString>,
    }

    impl TestCommandFactory {
        fn shell(script: &str) -> Self {
            Self {
                program: PathBuf::from("/bin/sh"),
                args: vec![OsString::from("-c"), OsString::from(script)],
            }
        }
    }

    impl CommandFactory for TestCommandFactory {
        fn build(&self, account: &AccountRecord) -> Result<CommandBuilder, PtyError> {
            let mut command = CommandBuilder::new(&self.program);
            command.args(&self.args);
            configure_clean_environment(&mut command, account);
            Ok(command)
        }
    }

    fn dimensions() -> Dimensions {
        Dimensions {
            cols: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        }
    }

    async fn test_session(script: &str) -> PtySession {
        PtySession::spawn_with_factory(dimensions(), Arc::new(TestCommandFactory::shell(script)))
            .await
            .unwrap()
    }

    async fn collect_output(session: &mut PtySession) -> Vec<u8> {
        let mut output = Vec::new();
        while let Some(chunk) = session.next_output().await {
            output.extend_from_slice(chunk.bytes());
        }
        output
    }

    async fn wait_for_output(session: &mut PtySession, needle: &[u8]) {
        let mut seen = Vec::new();
        while !seen.windows(needle.len()).any(|window| window == needle) {
            let chunk = session
                .next_output()
                .await
                .expect("child output before EOF");
            seen.extend_from_slice(chunk.bytes());
        }
    }

    #[test]
    fn production_login_shell_environment_is_clean_and_fixed() {
        let account = resolve_account().unwrap();
        let command = LoginShellCommandFactory.build(&account).unwrap();
        assert!(command.is_default_prog());
        assert_eq!(
            command.get_cwd(),
            Some(&account.home.as_os_str().to_owned())
        );
        let environment: std::collections::BTreeMap<_, _> = command
            .iter_full_env_as_str()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        assert_eq!(environment["TERM"], "xterm-256color");
        assert_eq!(environment["COLORTERM"], "truecolor");
        assert_eq!(environment["HOME"], account.home.to_string_lossy());
        assert_eq!(environment["USER"], account.name);
        assert!(!environment.contains_key("CIAO_PHASE1_RELAY_ONLY"));
        assert!(environment.keys().all(|key| {
            matches!(
                key.as_str(),
                "HOME"
                    | "USER"
                    | "LOGNAME"
                    | "SHELL"
                    | "PATH"
                    | "TMPDIR"
                    | "LANG"
                    | "SSH_AUTH_SOCK"
                    | "TERM"
                    | "COLORTERM"
            ) || key.starts_with("LC_")
        }));
    }

    #[tokio::test]
    async fn deterministic_child_bridges_bytes_and_preserves_split_unicode() {
        let mut session =
            test_session("printf '\\360\\237'; sleep 0.05; printf '\\221\\213'").await;
        let output = collect_output(&mut session).await;
        assert_eq!(output, vec![0xf0, 0x9f, 0x91, 0x8b]);
        assert_eq!(session.finish_normal().await.unwrap(), PtyExit::Exited(0));
    }

    #[tokio::test]
    async fn input_fifo_is_ordered_and_bounded() {
        let mut session =
            test_session("stty -echo -icanon min 1 time 0; dd bs=1 count=6 2>/dev/null").await;
        session.send_input(b"abc".to_vec()).await.unwrap();
        session.send_input(b"def".to_vec()).await.unwrap();
        let output = collect_output(&mut session).await;
        assert!(output.windows(6).any(|window| window == b"abcdef"));
        let marks = session.queue_high_water_marks();
        assert!(marks.input_bytes <= HOST_PENDING_INPUT_BYTES);
        assert!(marks.output_bytes <= HOST_PENDING_OUTPUT_BYTES);
        assert_eq!(session.finish_normal().await.unwrap(), PtyExit::Exited(0));
    }

    #[tokio::test]
    async fn viewer_cleanup_kills_before_any_graceful_signal() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("gasp");
        let script = format!(
            "trap 'touch {m}' HUP TERM; printf READY; while :; do sleep 1; done",
            m = marker.display()
        );
        let mut session = test_session(&script).await;
        wait_for_output(&mut session, b"READY").await;
        session.mark_viewer_cleanup();
        session.cleanup(CleanupReason::ExplicitClose).await.unwrap();
        assert!(
            !marker.exists(),
            "viewer child ran its trap; it saw a graceful signal before dying"
        );
    }

    /// Positive control for the trap above: without viewer cleanup the ladder's SIGHUP
    /// reaches the child and the trap runs. Proves the trap was installed and reachable,
    /// so the negative assertion cannot pass vacuously.
    #[tokio::test]
    async fn graceful_cleanup_still_signals_a_trapping_child() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("gasp");
        let script = format!(
            "trap 'touch {m}' HUP TERM; printf READY; while :; do sleep 1; done",
            m = marker.display()
        );
        let mut session = test_session(&script).await;
        wait_for_output(&mut session, b"READY").await;
        session.cleanup(CleanupReason::ExplicitClose).await.unwrap();
        assert!(
            marker.exists(),
            "graceful cleanup no longer signals children; the viewer test is vacuous"
        );
    }

    #[tokio::test]
    async fn resize_reaches_kernel_reported_window_size() {
        let mut session = test_session("sleep 0.2; stty size").await;
        session
            .request_resize(Dimensions {
                cols: 123,
                rows: 45,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let output = collect_output(&mut session).await;
        assert!(
            String::from_utf8_lossy(&output).contains("45 123"),
            "kernel did not report the final coalesced dimensions"
        );
        assert_eq!(session.finish_normal().await.unwrap(), PtyExit::Exited(0));
    }

    /// The reported stray-blank-line bug: a resize to the size the PTY already has still
    /// delivers SIGWINCH, and the TUI redrawing its composer on that signal is what leaves the
    /// line behind. The app replays its retained dimensions once per foreground, so this is the
    /// difference between one redundant signal per app open and none.
    #[tokio::test]
    async fn a_resize_to_the_current_size_delivers_no_sigwinch() {
        let mut session = test_session("trap 'echo WINCH' WINCH; sleep 0.6; echo done").await;
        // The signal must arrive after the shell installs the trap, or SIGWINCH's default
        // action — ignore — swallows it and the assertion below passes without testing
        // anything. This is the whole reason the paired positive control exists.
        tokio::time::sleep(Duration::from_millis(200)).await;
        session.request_resize(dimensions()).unwrap();
        let output = collect_output(&mut session).await;
        let text = String::from_utf8_lossy(&output);
        assert!(
            !text.contains("WINCH"),
            "redundant resize signalled the TUI: {text}"
        );
        assert!(
            text.contains("done"),
            "script never ran to completion: {text}"
        );
        assert_eq!(session.finish_normal().await.unwrap(), PtyExit::Exited(0));
    }

    /// Pairs with the test above so suppressing *every* resize cannot pass as a fix.
    #[tokio::test]
    async fn a_resize_that_changes_the_size_still_delivers_sigwinch() {
        let mut session = test_session("trap 'echo WINCH' WINCH; sleep 0.6; echo done").await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        session
            .request_resize(Dimensions {
                cols: 100,
                rows: 30,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let output = collect_output(&mut session).await;
        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("WINCH"),
            "a real resize did not signal the TUI: {text}"
        );
        assert_eq!(session.finish_normal().await.unwrap(), PtyExit::Exited(0));
    }

    #[tokio::test]
    async fn exit_status_and_signal_are_mapped() {
        let mut exited = test_session("exit 7").await;
        let _ = collect_output(&mut exited).await;
        assert_eq!(exited.finish_normal().await.unwrap(), PtyExit::Exited(7));

        let mut signaled = test_session("kill -TERM $$").await;
        let _ = collect_output(&mut signaled).await;
        assert_eq!(
            signaled.finish_normal().await.unwrap(),
            PtyExit::Signaled("SIGTERM".into())
        );
    }

    #[tokio::test]
    async fn explicit_cleanup_is_idempotent_and_reaps_child() {
        let mut session = test_session("sleep 300").await;
        let pid = session.child_pid();
        assert!(getsid(Some(pid)).is_ok());
        session.cleanup(CleanupReason::ExplicitClose).await.unwrap();
        session.cleanup(CleanupReason::ExplicitClose).await.unwrap();
        assert!(matches!(getsid(Some(pid)), Err(Errno::ESRCH)));
    }

    #[tokio::test]
    async fn reset_bridge_failure_and_shutdown_cleanup_all_reap_children() {
        for reason in [
            CleanupReason::StreamEnded,
            CleanupReason::BridgeFailure,
            CleanupReason::ServerShutdown,
        ] {
            let mut session = test_session("sleep 300").await;
            let pid = session.child_pid();
            session.cleanup(reason).await.unwrap();
            assert!(matches!(getsid(Some(pid)), Err(Errno::ESRCH)));
        }
    }

    #[tokio::test]
    async fn cleanup_reaps_foreground_child_process_group() {
        let marker = format!("ciao-phase1-{}", rand::random::<u64>());
        let script = format!("exec -a {marker} sleep 300");
        // macOS /bin/sh does not guarantee `exec -a`; use a shell-owned foreground sleep and
        // inspect only the process tree locally inside this disposable test.
        let mut session = test_session("sleep 300").await;
        let shell_pid = session.child_pid();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let output = Command::new("pgrep")
            .args(["-P", &shell_pid.as_raw().to_string(), "sleep"])
            .output()
            .unwrap();
        let child_pid = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .and_then(|line| line.parse::<i32>().ok())
            .map(Pid::from_raw);
        session
            .cleanup(CleanupReason::ConnectionLost)
            .await
            .unwrap();
        assert!(reaped(shell_pid).await, "the shell outlived cleanup");
        if let Some(child_pid) = child_pid {
            assert!(
                reaped(child_pid).await,
                "the foreground child outlived cleanup"
            );
        }
        drop(script);
    }

    /// Waits for a process to leave the table entirely.
    ///
    /// The group signal kills a foreground child at once, but the child then sits as a zombie
    /// until whoever inherits it reaps it, and `getsid` answers for a zombie exactly as it does
    /// for a live process. Asserting the instant cleanup returns therefore measures how quickly
    /// the system reaper got to it — which Ciao does not control and which is slow enough to fail
    /// on Linux under load — rather than whether cleanup killed anything.
    async fn reaped(pid: Pid) -> bool {
        for _ in 0..100 {
            if matches!(getsid(Some(pid)), Err(Errno::ESRCH)) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[tokio::test]
    async fn cancellation_unblocks_full_output_queue_and_reader_task() {
        let mut session = test_session("yes x").await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        session.cleanup(CleanupReason::BridgeFailure).await.unwrap();
        let marks = session.queue_high_water_marks();
        assert!(marks.output_bytes <= HOST_PENDING_OUTPUT_BYTES);
    }

    /// Runs the production tmux attach argv with one extra test-only environment variable
    /// (`TMUX_TMPDIR`) so the test talks to an isolated tmux server instead of the user's.
    struct IsolatedTmuxAttachFactory {
        program: PathBuf,
        args: Vec<OsString>,
        socket_dir: PathBuf,
    }

    impl CommandFactory for IsolatedTmuxAttachFactory {
        fn build(&self, account: &AccountRecord) -> Result<CommandBuilder, PtyError> {
            let mut command = CommandBuilder::new(&self.program);
            command.args(&self.args);
            configure_clean_environment(&mut command, account);
            command.env("TMUX_TMPDIR", &self.socket_dir);
            Ok(command)
        }
    }

    fn isolated_tmux(tmux: &Path, socket_dir: &Path) -> Command {
        let mut command = Command::new(tmux);
        command.env("TMUX_TMPDIR", socket_dir).env_remove("TMUX");
        command
    }

    /// Spec 003 §5.3/§12: closing a session-target terminal kills only the provider *client*.
    /// A real detached tmux session containing a sleeper must survive open→close untouched.
    // Spec 004 §8.3: portable across the accepted Unix hosts; Linux cleanup semantics are
    // additionally proven on the grounded VM/LXC profiles during physical acceptance.
    #[cfg(unix)]
    #[tokio::test]
    async fn tmux_session_and_sleeper_survive_ciao_client_detach() {
        let config = crate::workspace::WorkspaceConfig::for_home(&resolve_account().unwrap().home);
        let tmux = config
            .resolve(crate::host_protocol::ProviderKind::Tmux)
            .expect("tmux is required on the target Mac for the detach-survival test");
        let socket_dir = tempfile::tempdir().unwrap();
        let session_name = format!("ciao-detach-{}", rand::random::<u32>());
        let target = format!("={session_name}");

        let created = isolated_tmux(&tmux, socket_dir.path())
            .args(["new-session", "-d", "-s", &session_name, "sleep 300"])
            .status()
            .unwrap();
        assert!(
            created.success(),
            "could not create the isolated tmux session"
        );

        // Find the pane process; retry briefly while the fresh server settles.
        let mut pane_pid = None;
        for _ in 0..40 {
            let output = isolated_tmux(&tmux, socket_dir.path())
                .args(["list-panes", "-t", &target, "-F", "#{pane_pid}"])
                .output()
                .unwrap();
            if output.status.success()
                && let Some(pid) = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .and_then(|line| line.trim().parse::<i32>().ok())
            {
                pane_pid = Some(Pid::from_raw(pid));
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let pane_pid = pane_pid.expect("isolated tmux session has a pane process");

        // Attach exactly like production: the workspace argv table plus the isolation variable.
        let account = resolve_account().unwrap();
        let (program, args) = crate::workspace::target_command(
            crate::host_protocol::TerminalTarget::TmuxAttach,
            &session_name,
            &tmux,
            &account.home,
        )
        .unwrap();
        let mut client = PtySession::spawn_with_factory(
            dimensions(),
            Arc::new(IsolatedTmuxAttachFactory {
                program,
                args,
                socket_dir: socket_dir.path().to_owned(),
            }),
        )
        .await
        .unwrap();
        let client_pid = client.child_pid();
        // The attached client paints the screen; seeing output proves the attach succeeded.
        assert!(
            client.next_output().await.is_some(),
            "tmux attach produced no output"
        );

        // Close from Ciao: the Phase 1 escalation path must kill only the client.
        client.cleanup(CleanupReason::ExplicitClose).await.unwrap();
        assert!(matches!(getsid(Some(client_pid)), Err(Errno::ESRCH)));

        let survives = isolated_tmux(&tmux, socket_dir.path())
            .args(["has-session", "-t", &target])
            .status()
            .unwrap();
        assert!(
            survives.success(),
            "tmux session did not survive client detach"
        );
        assert!(
            nix::sys::signal::kill(pane_pid, None).is_ok(),
            "sleeper process did not survive client detach"
        );

        // The test cleans up its own isolated server and session.
        let killed = isolated_tmux(&tmux, socket_dir.path())
            .args(["kill-server"])
            .status()
            .unwrap();
        assert!(killed.success());
        for _ in 0..40 {
            if matches!(getsid(Some(pane_pid)), Err(Errno::ESRCH)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(matches!(getsid(Some(pane_pid)), Err(Errno::ESRCH)));
    }

    /// An interactive pane consumes terminal EOF and exits, unlike the sleeper above. Production
    /// close therefore detaches the exact Ciao client TTY before generic PTY cleanup.
    // Spec 004 §8.3: portable across the accepted Unix hosts; Linux cleanup semantics are
    // additionally proven on the grounded VM/LXC profiles during physical acceptance.
    #[cfg(unix)]
    #[tokio::test]
    async fn tmux_interactive_shell_survives_targeted_ciao_client_detach() {
        let config = crate::workspace::WorkspaceConfig::for_home(&resolve_account().unwrap().home);
        let tmux = config
            .resolve(crate::host_protocol::ProviderKind::Tmux)
            .expect("tmux is required on the target Mac for the interactive detach test");
        let session_name = format!("ciao-interactive-{}", rand::random::<u32>());
        let target = format!("={session_name}");
        let created = Command::new(&tmux)
            .env_remove("TMUX")
            .args(["new-session", "-d", "-s", &session_name, "/bin/sh"])
            .status()
            .unwrap();
        assert!(
            created.success(),
            "could not create interactive tmux session"
        );
        let pane_pid: i32 = Command::new(&tmux)
            .env_remove("TMUX")
            .args(["list-panes", "-t", &target, "-F", "#{pane_pid}"])
            .output()
            .unwrap()
            .stdout
            .split(|byte| *byte == b'\n')
            .next()
            .and_then(|line| std::str::from_utf8(line).ok())
            .and_then(|line| line.parse().ok())
            .expect("interactive pane has a process");

        let account = resolve_account().unwrap();
        let (program, args) = crate::workspace::target_command(
            crate::host_protocol::TerminalTarget::TmuxAttach,
            &session_name,
            &tmux,
            &account.home,
        )
        .unwrap();
        let mut client = PtySession::spawn_fixed_argv(dimensions(), program, args)
            .await
            .unwrap();
        timeout(Duration::from_secs(5), client.next_output())
            .await
            .expect("tmux attach produced no output");
        let client_tty = client.client_tty().unwrap().to_owned();
        assert!(crate::workspace::detach_tmux_client(&tmux, &client_tty).await);
        client.cleanup(CleanupReason::ExplicitClose).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            Command::new(&tmux)
                .env_remove("TMUX")
                .args(["has-session", "-t", &target])
                .status()
                .unwrap()
                .success(),
            "tmux session did not survive targeted client detach"
        );
        assert!(
            nix::sys::signal::kill(Pid::from_raw(pane_pid), None).is_ok(),
            "interactive pane did not survive targeted client detach"
        );
        assert!(
            Command::new(&tmux)
                .env_remove("TMUX")
                .args(["kill-session", "-t", &target])
                .status()
                .unwrap()
                .success(),
            "could not clean up interactive detach session"
        );
    }

    /// Creation starts the tmux server from inside Ciao's PTY. Closing the provider client must
    /// not signal that newly spawned server's process group or the session disappears immediately.
    // Spec 004 §8.3: portable across the accepted Unix hosts; Linux cleanup semantics are
    // additionally proven on the grounded VM/LXC profiles during physical acceptance.
    #[cfg(unix)]
    #[tokio::test]
    async fn tmux_created_session_survives_ciao_client_cleanup() {
        let config = crate::workspace::WorkspaceConfig::for_home(&resolve_account().unwrap().home);
        let tmux = config
            .resolve(crate::host_protocol::ProviderKind::Tmux)
            .expect("tmux is required on the target Mac for the create-survival test");
        let socket_dir = tempfile::tempdir().unwrap();
        let session_name = format!("ciao-create-{}", rand::random::<u32>());
        let account = resolve_account().unwrap();
        let (program, args) = crate::workspace::target_command(
            crate::host_protocol::TerminalTarget::TmuxCreate,
            &session_name,
            &tmux,
            &account.home,
        )
        .unwrap();
        let mut client = PtySession::spawn_with_factory(
            dimensions(),
            Arc::new(IsolatedTmuxAttachFactory {
                program,
                args,
                socket_dir: socket_dir.path().to_owned(),
            }),
        )
        .await
        .unwrap();
        timeout(Duration::from_secs(5), client.next_output())
            .await
            .expect("tmux create produced no output");

        // Establishment is a precondition, not a nicety. First client output does not mean the
        // server has created the session, so cleaning up here used to run *before* the session
        // existed and then observe the one the already-forked server went on to create. That
        // passed while asserting nothing, which is why the failure looked intermittent.
        let target = format!("={session_name}");
        let deadline = Instant::now() + Duration::from_secs(10);
        let established = loop {
            if isolated_tmux(&tmux, socket_dir.path())
                .args(["has-session", "-t", &target])
                .status()
                .is_ok_and(|status| status.success())
            {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert!(
            established,
            "tmux never established the session, so the survival assertion would be vacuous"
        );

        // Mirror the production close sequence. `cleanup_terminal` detaches the tmux client
        // before tearing the PTY down; calling `cleanup` alone kills the client while it is
        // still attached, which takes the freshly created server with it. That is a path
        // production never takes, so asserting against it measured the wrong thing.
        // `detach_tmux_client` cannot be reused here because it invokes tmux without this
        // test's `-S` socket and would address the production server instead.
        let client_tty = client
            .client_tty()
            .map(|tty| tty.to_string_lossy().into_owned())
            .expect("the tmux client must have a tty to detach");
        let detached = isolated_tmux(&tmux, socket_dir.path())
            .args(["detach-client", "-t", &client_tty])
            .status()
            .unwrap()
            .success();
        assert!(detached, "could not detach the tmux client before cleanup");

        client.cleanup(CleanupReason::ExplicitClose).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let survived = isolated_tmux(&tmux, socket_dir.path())
            .args(["has-session", "-t", &target])
            .status()
            .unwrap()
            .success();
        if survived {
            let _ = isolated_tmux(&tmux, socket_dir.path())
                .args(["kill-server"])
                .status();
        }
        assert!(survived, "new tmux session died with the Ciao client");
    }

    /// Uses the production socket/environment rather than a test-only TMUX_TMPDIR: a session
    /// created through Ciao must be visible to the next production workspace snapshot.
    // Spec 004 §8.3: portable across the accepted Unix hosts; Linux cleanup semantics are
    // additionally proven on the grounded VM/LXC profiles during physical acceptance.
    #[cfg(unix)]
    #[tokio::test]
    async fn tmux_created_session_is_rediscovered_by_production_snapshot() {
        let config = crate::workspace::WorkspaceConfig::for_home(&resolve_account().unwrap().home);
        let tmux = config
            .resolve(crate::host_protocol::ProviderKind::Tmux)
            .expect("tmux is required on the target Mac for the rediscovery test");
        let session_name = format!("ciao-rediscover-{}", rand::random::<u32>());
        let account = resolve_account().unwrap();
        let (program, args) = crate::workspace::target_command(
            crate::host_protocol::TerminalTarget::TmuxCreate,
            &session_name,
            &tmux,
            &account.home,
        )
        .unwrap();
        let mut client = PtySession::spawn_fixed_argv(dimensions(), program, args)
            .await
            .unwrap();
        timeout(Duration::from_secs(5), client.next_output())
            .await
            .expect("tmux create produced no output");

        // Same two corrections as the survival test above: wait for the server to actually
        // establish the session, then detach the way `cleanup_terminal` does before tearing
        // the PTY down. On the production socket the real helper is usable directly.
        let target = format!("={session_name}");
        let deadline = Instant::now() + Duration::from_secs(10);
        let established = loop {
            if Command::new(&tmux)
                .env_remove("TMUX")
                .args(["has-session", "-t", &target])
                .status()
                .is_ok_and(|status| status.success())
            {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert!(
            established,
            "tmux never established the session, so rediscovery would be vacuous"
        );
        if let Some(tty) = client.client_tty().map(|tty| tty.to_owned()) {
            assert!(
                crate::workspace::detach_tmux_client(&tmux, &tty).await,
                "could not detach the tmux client before cleanup"
            );
        }
        client.cleanup(CleanupReason::ExplicitClose).await.unwrap();

        let snapshot = crate::workspace::capture_snapshot(&config, None).await;
        let rediscovered = snapshot
            .providers
            .tmux
            .sessions
            .as_deref()
            .is_some_and(|sessions| sessions.iter().any(|session| session.name == session_name));

        let target = format!("={session_name}");
        let cleanup = Command::new(&tmux)
            .env_remove("TMUX")
            .args(["kill-session", "-t", &target])
            .status()
            .unwrap();
        assert!(
            cleanup.success(),
            "could not clean up the rediscovery session"
        );
        assert!(
            rediscovered,
            "Ciao-created tmux session was absent from the next snapshot"
        );
    }
}
