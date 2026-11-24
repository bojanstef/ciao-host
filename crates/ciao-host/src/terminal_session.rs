//! The daemon owns one terminal bridge policy; only its local byte source differs.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use crate::{
    herdr_core::{CoreConfig, CoreExitWatcher, CoreOutput, CoreSession},
    host_protocol::Dimensions,
    pty::{
        CleanupReason, PtyError, PtyExit, PtyExitWatcher, PtyOutput, PtySession,
        QueueHighWaterMarks,
    },
};

pub(crate) enum TerminalSession {
    Pty(PtySession),
    Core(CoreSession),
    Orca(crate::orca::session::OrcaSession),
}
pub(crate) enum TerminalOutput {
    Pty(PtyOutput),
    Core(CoreOutput),
    Orca(Vec<u8>),
}
pub(crate) enum TerminalExitWatcher {
    Pty(PtyExitWatcher),
    Core(CoreExitWatcher),
    Orca(tokio::sync::watch::Receiver<Option<Result<PtyExit, PtyError>>>),
}

impl TerminalOutput {
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Pty(output) => output.bytes(),
            Self::Core(output) => output.bytes(),
            Self::Orca(bytes) => bytes,
        }
    }
}
impl TerminalExitWatcher {
    pub(crate) async fn wait(&mut self) -> Result<PtyExit, PtyError> {
        match self {
            Self::Pty(watcher) => watcher.wait().await,
            Self::Core(watcher) => watcher.wait().await,
            Self::Orca(rx) => rx
                .wait_for(Option::is_some)
                .await
                .map_err(|_| PtyError::WaitFailed)?
                .clone()
                .ok_or(PtyError::WaitFailed)?,
        }
    }
}
impl TerminalSession {
    pub(crate) async fn spawn_login_shell(size: Dimensions) -> Result<Self, PtyError> {
        PtySession::spawn_login_shell(size).await.map(Self::Pty)
    }
    pub(crate) async fn spawn_fixed_argv(
        size: Dimensions,
        program: PathBuf,
        args: Vec<OsString>,
    ) -> Result<Self, PtyError> {
        PtySession::spawn_fixed_argv(size, program, args)
            .await
            .map(Self::Pty)
    }
    pub(crate) async fn attach_core(
        config: CoreConfig,
        session: String,
        tab: String,
        size: Dimensions,
    ) -> Result<Self, PtyError> {
        CoreSession::attach(config, session, tab, size)
            .await
            .map(Self::Core)
    }
    pub(crate) fn terminal_id(&self) -> &str {
        match self {
            Self::Pty(session) => session.terminal_id(),
            Self::Core(session) => session.terminal_id(),
            Self::Orca(session) => &session.id,
        }
    }
    pub(crate) fn mark_viewer_cleanup(&mut self) {
        if let Self::Pty(session) = self {
            session.mark_viewer_cleanup();
        }
    }
    pub(crate) fn client_tty(&self) -> Option<&Path> {
        match self {
            Self::Pty(session) => session.client_tty(),
            Self::Core(_) | Self::Orca(_) => None,
        }
    }
    pub(crate) fn exit_watcher(&self) -> TerminalExitWatcher {
        match self {
            Self::Pty(session) => TerminalExitWatcher::Pty(session.exit_watcher()),
            Self::Core(session) => TerminalExitWatcher::Core(session.exit_watcher()),
            Self::Orca(session) => TerminalExitWatcher::Orca(session.exit.clone()),
        }
    }
    pub(crate) async fn next_output(&mut self) -> Option<TerminalOutput> {
        match self {
            Self::Pty(session) => session.next_output().await.map(TerminalOutput::Pty),
            Self::Core(session) => session.next_output().await.map(TerminalOutput::Core),
            Self::Orca(session) => session.next_output().await.map(TerminalOutput::Orca),
        }
    }
    pub(crate) async fn send_input(&self, bytes: Vec<u8>) -> Result<(), PtyError> {
        match self {
            Self::Pty(session) => session.send_input(bytes).await,
            Self::Core(session) => session.send_input(bytes).await,
            Self::Orca(session) => session.send_input(bytes).await,
        }
    }
    pub(crate) fn request_resize(&self, size: Dimensions) -> Result<(), PtyError> {
        match self {
            Self::Pty(session) => session.request_resize(size),
            Self::Core(session) => session.request_resize(size),
            Self::Orca(session) => session.resize(size),
        }
    }
    pub(crate) fn queue_high_water_marks(&self) -> QueueHighWaterMarks {
        match self {
            Self::Pty(session) => session.queue_high_water_marks(),
            Self::Core(session) => session.queue_high_water_marks(),
            Self::Orca(session) => session.high_water(),
        }
    }
    pub(crate) async fn cleanup(&mut self, reason: CleanupReason) -> Result<(), PtyError> {
        match self {
            Self::Pty(session) => session.cleanup(reason).await.map(|_| ()),
            Self::Core(session) => session.cleanup(reason).await,
            Self::Orca(session) => session.cleanup().await,
        }
    }
    pub(crate) async fn finish_normal(&mut self) -> Result<PtyExit, PtyError> {
        match self {
            Self::Pty(session) => session.finish_normal().await,
            Self::Core(session) => session.finish_normal().await,
            Self::Orca(session) => session.exit.borrow().clone().ok_or(PtyError::WaitFailed)?,
        }
    }
}
