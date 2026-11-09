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
}
pub(crate) enum TerminalOutput {
    Pty(PtyOutput),
    Core(CoreOutput),
}
pub(crate) enum TerminalExitWatcher {
    Pty(PtyExitWatcher),
    Core(CoreExitWatcher),
}

impl TerminalOutput {
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Pty(output) => output.bytes(),
            Self::Core(output) => output.bytes(),
        }
    }
}
impl TerminalExitWatcher {
    pub(crate) async fn wait(&mut self) -> Result<PtyExit, PtyError> {
        match self {
            Self::Pty(watcher) => watcher.wait().await,
            Self::Core(watcher) => watcher.wait().await,
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
            Self::Core(_) => None,
        }
    }
    pub(crate) fn exit_watcher(&self) -> TerminalExitWatcher {
        match self {
            Self::Pty(session) => TerminalExitWatcher::Pty(session.exit_watcher()),
            Self::Core(session) => TerminalExitWatcher::Core(session.exit_watcher()),
        }
    }
    pub(crate) async fn next_output(&mut self) -> Option<TerminalOutput> {
        match self {
            Self::Pty(session) => session.next_output().await.map(TerminalOutput::Pty),
            Self::Core(session) => session.next_output().await.map(TerminalOutput::Core),
        }
    }
    pub(crate) async fn send_input(&self, bytes: Vec<u8>) -> Result<(), PtyError> {
        match self {
            Self::Pty(session) => session.send_input(bytes).await,
            Self::Core(session) => session.send_input(bytes).await,
        }
    }
    pub(crate) fn request_resize(&self, size: Dimensions) -> Result<(), PtyError> {
        match self {
            Self::Pty(session) => session.request_resize(size),
            Self::Core(session) => session.request_resize(size),
        }
    }
    pub(crate) fn queue_high_water_marks(&self) -> QueueHighWaterMarks {
        match self {
            Self::Pty(session) => session.queue_high_water_marks(),
            Self::Core(session) => session.queue_high_water_marks(),
        }
    }
    pub(crate) async fn cleanup(&mut self, reason: CleanupReason) -> Result<(), PtyError> {
        match self {
            Self::Pty(session) => session.cleanup(reason).await.map(|_| ()),
            Self::Core(session) => session.cleanup(reason).await,
        }
    }
    pub(crate) async fn finish_normal(&mut self) -> Result<PtyExit, PtyError> {
        match self {
            Self::Pty(session) => session.finish_normal().await,
            Self::Core(session) => session.finish_normal().await,
        }
    }
}
