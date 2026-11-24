use anyhow::{Result, bail};
use clap::Subcommand;
use serde_json::{Value, json};
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{
    agent_protocol::MAX_PROMPT_BYTES,
    ipc,
    peers::{
        Action, Admin, Descriptor, FollowMode, GrantScope, Outgoing, PeerAgent, SnapshotVersion,
    },
};

/// While nothing changes, follow still prints a snapshot this often.
const FOLLOW_HEARTBEAT: Duration = Duration::from_secs(1);
/// Follow asks again no sooner than this after its last request, so a burst of changes
/// prints at most four lines a second.
const FOLLOW_MIN_INTERVAL: Duration = Duration::from_millis(250);
/// The polling period against a destination that cannot wait for changes.
const FOLLOW_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// One follow reply: a session snapshot, and how it came.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct FollowStep {
    pub mode: FollowMode,
    pub snapshot: Value,
}

/// Where `follow` reads a remote session from.
pub(crate) trait FollowSource {
    /// The snapshot once it no longer matches `after`, or after `wait`. `None` when the
    /// local daemon predates this request.
    async fn changed(
        &self,
        after: Option<SnapshotVersion>,
        wait: Duration,
    ) -> Result<Option<FollowStep>>;

    /// The current snapshot.
    async fn snapshot(&self) -> Result<Value>;
}

/// Print a remote session for `seconds`: a line on each change, and at least one a second.
/// Against a destination or daemon that cannot wait for changes, poll once a second.
pub(crate) async fn follow(
    source: &impl FollowSource,
    seconds: Duration,
    mut emit: impl FnMut(&Value) -> Result<()>,
) -> Result<()> {
    let until = tokio::time::Instant::now() + seconds;
    let mut after = None;
    let mut changes = true;
    let mut printed = tokio::time::Instant::now();
    loop {
        let asked = tokio::time::Instant::now();
        let step = if changes {
            // Wait no later than the next heartbeat line, and no later than the end.
            let wait = (printed + FOLLOW_HEARTBEAT)
                .min(until)
                .saturating_duration_since(asked)
                .clamp(Duration::from_millis(1), FOLLOW_HEARTBEAT);
            source.changed(after, wait).await?
        } else {
            None
        };
        let step = match step {
            Some(step) => step,
            None => {
                changes = false;
                FollowStep {
                    mode: FollowMode::Polled,
                    snapshot: source.snapshot().await?,
                }
            }
        };
        emit(&step.snapshot)?;
        after = SnapshotVersion::of_value(&step.snapshot);
        let now = tokio::time::Instant::now();
        printed = now;
        let next = match step.mode {
            FollowMode::Pushed => asked + FOLLOW_MIN_INTERVAL,
            FollowMode::Polled => now + FOLLOW_POLL_INTERVAL,
        };
        if now >= until || next >= until {
            return Ok(());
        }
        tokio::time::sleep_until(next).await;
    }
}

/// The local daemon, which reaches the destination.
pub(crate) struct DaemonFollow<'a> {
    socket: &'a Path,
    host: String,
    session: String,
}

impl<'a> DaemonFollow<'a> {
    pub(crate) fn new(socket: &'a Path, host: String, session: String) -> Self {
        Self {
            socket,
            host,
            session,
        }
    }
}

impl FollowSource for DaemonFollow<'_> {
    async fn changed(
        &self,
        after: Option<SnapshotVersion>,
        wait: Duration,
    ) -> Result<Option<FollowStep>> {
        let wait_ms = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX);
        match ipc::request_peers(
            self.socket,
            json!({"op":"follow", "host":self.host, "session_id":self.session, "after":after, "wait_ms":wait_ms}),
        )
        .await
        {
            Ok(value) => Ok(Some(serde_json::from_value(value)?)),
            // An older daemon does not know this request.
            Err(ipc::IpcError::Daemon { code, .. }) if code == "invalid_request" => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn snapshot(&self) -> Result<Value> {
        Ok(ipc::request_peers(
            self.socket,
            json!({"op":"call", "host":self.host, "action":Action::Snapshot {session_id:self.session.clone()}}),
        )
        .await?)
    }
}

/// `--workspace` (repeatable) or `--all`, exactly one.
#[derive(Debug, clap::Args)]
#[group(required = true, multiple = false)]
pub(crate) struct ScopeArgs {
    /// A destination workspace ID from `peers list`; repeat for several
    #[arg(long)]
    workspace: Vec<String>,
    /// Every project on this host, including ones added later
    #[arg(long)]
    all: bool,
}

impl From<ScopeArgs> for GrantScope {
    fn from(args: ScopeArgs) -> Self {
        if args.all {
            Self::All
        } else {
            Self::Selected(args.workspace)
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Show this host's identity, incoming grants, outgoing links and selectable workspaces
    List,
    /// Allow one source host to launch agents in selected workspaces, or all of them, on this host
    Grant {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        name: String,
        #[command(flatten)]
        scope: ScopeArgs,
    },
    /// Change which workspaces an existing incoming grant covers; its link stays valid
    Update {
        #[arg(long)]
        endpoint: String,
        #[command(flatten)]
        scope: ScopeArgs,
    },
    /// Remember the destination link JSON returned by `peers grant` (or introduced by the phone)
    Remember {
        #[arg(long)]
        file: PathBuf,
    },
    /// Remove an exact endpoint ID's incoming grant on this host; running workers continue
    Revoke { endpoint: String },
    /// Drop this host's outgoing link to an exact endpoint ID; the destination keeps its grant
    Forget { endpoint: String },
    /// Ask a linked destination which of your granted workspaces are currently available
    Workspaces {
        #[arg(long)]
        host: String,
    },
    /// Start an agent in a workspace on a linked destination; reuse request-id to reconcile a lost reply
    Start {
        #[arg(long, value_enum, default_value = "claude")]
        agent: PeerAgent,
        #[arg(long)]
        host: String,
        #[arg(long)]
        workspace: String,
        #[arg(long)]
        request_id: String,
    },
    /// Read one session created under this link (the canonical Ciao snapshot, as JSON)
    Snapshot {
        #[arg(long)]
        host: String,
        session: String,
    },
    /// Follow a remote session for a bounded interval; each snapshot is one JSON line
    Follow {
        #[arg(long)]
        host: String,
        session: String,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=3600))]
        seconds: u64,
    },
    /// Submit a prompt; read UTF-8 from a bounded file, or from stdin when --prompt-file is -
    Send {
        #[arg(long)]
        host: String,
        session: String,
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        prompt_file: PathBuf,
    },
    /// Interrupt a turn in a session created under this link
    Interrupt {
        #[arg(long)]
        host: String,
        session: String,
        #[arg(long)]
        request_id: String,
    },
    /// Stop a worker created under this link; the conversation remains on the destination
    Stop {
        #[arg(long)]
        host: String,
        session: String,
        #[arg(long)]
        request_id: String,
    },
}

pub(crate) async fn run(command: Command, socket: &Path) -> Result<()> {
    let body = match command {
        Command::List => json!({"op":"admin", "action":Admin::Describe {}}),
        Command::Grant {
            endpoint,
            name,
            scope,
        } => {
            json!({"op":"admin", "action":Admin::Grant { peer:Descriptor {endpoint_id:endpoint, name}, scope:scope.into() }})
        }
        Command::Update { endpoint, scope } => {
            json!({"op":"admin", "action":Admin::Update { endpoint_id:endpoint, scope:scope.into() }})
        }
        Command::Remember { file } => {
            let link: Outgoing = serde_json::from_slice(&read_bounded(&file, 4096)?)?;
            json!({"op":"admin", "action":Admin::Remember {link}})
        }
        Command::Revoke { endpoint } => {
            json!({"op":"admin", "action":Admin::Revoke {endpoint_id:endpoint}})
        }
        Command::Forget { endpoint } => {
            json!({"op":"admin", "action":Admin::Forget {endpoint_id:endpoint}})
        }
        Command::Workspaces { host } => {
            json!({"op":"call", "host":host, "action":Action::Workspaces {}})
        }
        Command::Start {
            agent,
            host,
            workspace,
            request_id,
        } => {
            json!({"op":"call", "host":host, "action":Action::Start {agent, request_id, workspace_id:workspace}})
        }
        Command::Snapshot { host, session } => {
            json!({"op":"call", "host":host, "action":Action::Snapshot {session_id:session}})
        }
        Command::Send {
            host,
            session,
            request_id,
            prompt_file,
        } => {
            let text = String::from_utf8(read_bounded(&prompt_file, MAX_PROMPT_BYTES)?)?;
            json!({"op":"send", "host":host, "session_id":session, "request_id":request_id, "text":text})
        }
        Command::Interrupt {
            host,
            session,
            request_id,
        } => {
            json!({"op":"send", "host":host, "session_id":session, "request_id":request_id, "text":null})
        }
        Command::Stop {
            host,
            session,
            request_id,
        } => json!({"op":"stop", "host":host, "session_id":session, "request_id":request_id}),
        Command::Follow {
            host,
            session,
            seconds,
        } => {
            let source = DaemonFollow::new(socket, host, session);
            return follow(&source, Duration::from_secs(seconds), |snapshot| {
                println!("{}", serde_json::to_string(snapshot)?);
                Ok(())
            })
            .await;
        }
    };
    let value: Value = ipc::request_peers(socket, body).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let reader: Box<dyn Read> = if path == Path::new("-") {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(path)?)
    };
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > limit {
        bail!("input must contain 1..{limit} bytes");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use tokio::time::Instant;

    /// One request the loop made: when, with which version, and the wait (none for a poll).
    struct Asked {
        at: Duration,
        after: Option<SnapshotVersion>,
        wait: Option<Duration>,
    }

    /// A destination whose session changes every `change_every`, if at all.
    struct Scripted {
        mode: Option<FollowMode>,
        change_every: Option<Duration>,
        began: Instant,
        asked: RefCell<Vec<Asked>>,
        polls: Cell<usize>,
    }

    impl Scripted {
        fn new(mode: Option<FollowMode>, change_every: Option<Duration>) -> Self {
            Self {
                mode,
                change_every,
                began: Instant::now(),
                asked: RefCell::default(),
                polls: Cell::new(0),
            }
        }

        fn current(&self) -> Value {
            let revision = self.change_every.map_or(1, |every| {
                1 + (self.began.elapsed().as_millis() / every.as_millis()) as u64
            });
            json!({"snapshot_epoch":1, "process_generation":1, "revision":revision})
        }
    }

    impl FollowSource for Scripted {
        async fn changed(
            &self,
            after: Option<SnapshotVersion>,
            wait: Duration,
        ) -> Result<Option<FollowStep>> {
            self.asked.borrow_mut().push(Asked {
                at: self.began.elapsed(),
                after,
                wait: Some(wait),
            });
            let Some(mode) = self.mode else {
                return Ok(None);
            };
            if mode == FollowMode::Pushed
                && after.is_some()
                && SnapshotVersion::of_value(&self.current()) == after
            {
                let until_change = self.change_every.map_or(wait, |every| {
                    every
                        - Duration::from_millis(
                            (self.began.elapsed().as_millis() % every.as_millis()) as u64,
                        )
                });
                tokio::time::sleep(wait.min(until_change)).await;
            }
            Ok(Some(FollowStep {
                mode,
                snapshot: self.current(),
            }))
        }

        async fn snapshot(&self) -> Result<Value> {
            self.asked.borrow_mut().push(Asked {
                at: self.began.elapsed(),
                after: None,
                wait: None,
            });
            self.polls.set(self.polls.get() + 1);
            Ok(self.current())
        }
    }

    async fn run(source: &Scripted, seconds: u64) -> Vec<Duration> {
        let mut lines = Vec::new();
        follow(source, Duration::from_secs(seconds), |_| {
            lines.push(source.began.elapsed());
            Ok(())
        })
        .await
        .unwrap();
        lines
    }

    #[tokio::test(start_paused = true)]
    async fn peer_follow_prints_every_second_while_unchanged_and_soon_after_a_change() {
        let quiet = Scripted::new(Some(FollowMode::Pushed), None);
        let lines = run(&quiet, 5).await;
        {
            let asked = quiet.asked.borrow();
            assert!(asked[0].after.is_none() && asked[1..].iter().all(|a| a.after.is_some()));
            assert!(asked.iter().all(|a| a.wait.unwrap() <= FOLLOW_HEARTBEAT));
        }
        assert!(lines.windows(2).all(|w| w[1] - w[0] <= FOLLOW_HEARTBEAT));
        assert!(*lines.last().unwrap() <= Duration::from_secs(5));
        assert_eq!(quiet.polls.get(), 0);

        // Constant change: a line per request, requests at least 250 ms apart.
        let busy = Scripted::new(Some(FollowMode::Pushed), Some(Duration::from_millis(10)));
        let lines = run(&busy, 2).await;
        assert!(
            busy.asked
                .borrow()
                .windows(2)
                .all(|w| w[1].at - w[0].at >= FOLLOW_MIN_INTERVAL)
        );
        assert!(lines.len() <= 9, "{lines:?}");

        // A change after a quiet stretch prints at once.
        let once = Scripted::new(Some(FollowMode::Pushed), Some(Duration::from_millis(2600)));
        let lines = run(&once, 4).await;
        assert!(lines.contains(&Duration::from_millis(2600)), "{lines:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn peer_follow_polls_once_a_second_against_older_destinations_and_daemons() {
        let old_destination = Scripted::new(Some(FollowMode::Polled), None);
        let lines = run(&old_destination, 4).await;
        assert!(
            lines
                .windows(2)
                .all(|w| w[1] - w[0] >= FOLLOW_POLL_INTERVAL)
        );
        assert_eq!(lines.len(), 4);

        // A daemon that does not know `follow` is asked once, then polled for snapshots.
        let old_daemon = Scripted::new(None, None);
        let lines = run(&old_daemon, 4).await;
        let waits = old_daemon
            .asked
            .borrow()
            .iter()
            .filter(|a| a.wait.is_some())
            .count();
        assert_eq!(waits, 1);
        assert_eq!(old_daemon.polls.get(), lines.len());
        assert!(
            lines
                .windows(2)
                .all(|w| w[1] - w[0] >= FOLLOW_POLL_INTERVAL)
        );
        assert_eq!(lines.len(), 4);
    }
}
