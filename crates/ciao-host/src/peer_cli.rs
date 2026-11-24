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

/// After this long with nothing new to print, follow prints a heartbeat line.
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

/// The `type` of a follow line that is not a snapshot. Snapshot lines have no `type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FollowLineType {
    Heartbeat,
}

/// Nothing changed for a second and the link is alive. It names the snapshot the follower
/// already holds, and carries no conversation content.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Heartbeat {
    #[serde(rename = "type")]
    pub kind: FollowLineType,
    pub session_id: String,
    #[serde(flatten)]
    pub holds: Option<SnapshotVersion>,
}

/// One line `follow` prints.
#[derive(Debug)]
pub(crate) enum FollowLine<'a> {
    /// The canonical snapshot, printed only when it differs from the last one printed.
    Snapshot(&'a Value),
    Heartbeat(Heartbeat),
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

/// Follow a remote session for `seconds`. A snapshot is printed when it differs from the last
/// one printed, and a heartbeat after a second with nothing new. The same holds whether the
/// destination waits for changes or this side polls it once a second (a destination or local
/// daemon that cannot wait). A failed read ends the follow with its error.
pub(crate) async fn follow(
    source: &impl FollowSource,
    session_id: &str,
    seconds: Duration,
    mut emit: impl FnMut(FollowLine<'_>) -> Result<()>,
) -> Result<()> {
    let until = tokio::time::Instant::now() + seconds;
    let mut last: Option<Value> = None;
    let mut changes = true;
    let mut printed = tokio::time::Instant::now();
    loop {
        let asked = tokio::time::Instant::now();
        let after = last.as_ref().and_then(SnapshotVersion::of_value);
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
        let now = tokio::time::Instant::now();
        if last.as_ref() != Some(&step.snapshot) {
            emit(FollowLine::Snapshot(&step.snapshot))?;
            last = Some(step.snapshot);
            printed = now;
        } else if now.duration_since(printed) >= FOLLOW_HEARTBEAT {
            emit(FollowLine::Heartbeat(Heartbeat {
                kind: FollowLineType::Heartbeat,
                session_id: session_id.into(),
                holds: after,
            }))?;
            printed = now;
        }
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
        // Rounded up, so an unchanged reply never comes back before the heartbeat is due.
        let wait_ms = u32::try_from(wait.as_micros().div_ceil(1000)).unwrap_or(u32::MAX);
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
    /// Follow a remote session for a bounded interval: each changed snapshot is one JSON line,
    /// and a {"type":"heartbeat"} line follows each second with no change
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
            let source = DaemonFollow::new(socket, host, session.clone());
            return follow(&source, &session, Duration::from_secs(seconds), |line| {
                match line {
                    FollowLine::Snapshot(snapshot) => {
                        println!("{}", serde_json::to_string(snapshot)?);
                    }
                    FollowLine::Heartbeat(heartbeat) => {
                        println!("{}", serde_json::to_string(&heartbeat)?);
                    }
                }
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

    /// A destination whose session changes at `changes` (or every `every`), and how it answers.
    struct Scripted {
        mode: Option<FollowMode>,
        every: Option<Duration>,
        changes: Vec<Duration>,
        began: Instant,
        asked: RefCell<Vec<Asked>>,
        polls: Cell<usize>,
    }

    impl Scripted {
        fn new(mode: Option<FollowMode>) -> Self {
            Self {
                mode,
                every: None,
                changes: Vec::new(),
                began: Instant::now(),
                asked: RefCell::default(),
                polls: Cell::new(0),
            }
        }

        fn changing_at(mut self, changes: &[u64]) -> Self {
            self.changes = changes
                .iter()
                .map(|ms| Duration::from_millis(*ms))
                .collect();
            self
        }

        fn changing_every(mut self, every: Duration) -> Self {
            self.every = Some(every);
            self
        }

        fn revision_at(&self, at: Duration) -> u64 {
            let scheduled = self.changes.iter().filter(|c| **c <= at).count() as u64;
            let periodic = self
                .every
                .map_or(0, |every| (at.as_millis() / every.as_millis()) as u64);
            1 + scheduled + periodic
        }

        fn current(&self) -> Value {
            let revision = self.revision_at(self.began.elapsed());
            json!({"session_id":"s", "snapshot_epoch":1, "process_generation":1, "revision":revision})
        }

        /// When the next change after now happens, if any.
        fn next_change(&self) -> Option<Duration> {
            let now = self.began.elapsed();
            let scheduled = self.changes.iter().copied().find(|c| *c > now);
            let periodic = self
                .every
                .map(|every| every * (now.as_millis() / every.as_millis() + 1) as u32);
            scheduled.into_iter().chain(periodic).min()
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
                let until_change = self
                    .next_change()
                    .map_or(wait, |at| at - self.began.elapsed());
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

    /// What follow printed, when, and the revision the line names.
    #[derive(Debug, PartialEq)]
    enum Printed {
        Snapshot(Duration, u64),
        Heartbeat(Duration, u64),
    }

    impl Printed {
        fn at(&self) -> Duration {
            match self {
                Self::Snapshot(at, _) | Self::Heartbeat(at, _) => *at,
            }
        }
    }

    async fn run(source: &Scripted, seconds: u64) -> Vec<Printed> {
        let mut lines = Vec::new();
        follow(source, "s", Duration::from_secs(seconds), |line| {
            let at = source.began.elapsed();
            lines.push(match line {
                FollowLine::Snapshot(snapshot) => {
                    Printed::Snapshot(at, snapshot["revision"].as_u64().unwrap())
                }
                FollowLine::Heartbeat(heartbeat) => {
                    Printed::Heartbeat(at, heartbeat.holds.unwrap().revision)
                }
            });
            Ok(())
        })
        .await
        .unwrap();
        lines
    }

    fn ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    #[test]
    fn peer_follow_heartbeat_is_small_typed_and_names_the_held_snapshot() {
        let heartbeat = Heartbeat {
            kind: FollowLineType::Heartbeat,
            session_id: "s".into(),
            holds: Some(SnapshotVersion {
                snapshot_epoch: 3,
                process_generation: 2,
                revision: 41,
            }),
        };
        assert_eq!(
            serde_json::to_string(&heartbeat).unwrap(),
            r#"{"type":"heartbeat","session_id":"s","snapshot_epoch":3,"process_generation":2,"revision":41}"#
        );
    }

    #[tokio::test(start_paused = true)]
    async fn peer_follow_prints_a_change_once_and_a_heartbeat_after_each_quiet_second() {
        let quiet = Scripted::new(Some(FollowMode::Pushed));
        assert_eq!(
            run(&quiet, 3).await,
            [
                Printed::Snapshot(ms(0), 1),
                Printed::Heartbeat(ms(1000), 1),
                Printed::Heartbeat(ms(2000), 1),
                Printed::Heartbeat(ms(3000), 1),
            ]
        );
        {
            let asked = quiet.asked.borrow();
            assert!(asked[0].after.is_none() && asked[1..].iter().all(|a| a.after.is_some()));
            assert!(asked.iter().all(|a| a.wait.unwrap() <= FOLLOW_HEARTBEAT));
        }
        assert_eq!(quiet.polls.get(), 0);

        // A change after a quiet stretch prints at once, once.
        let once = Scripted::new(Some(FollowMode::Pushed)).changing_at(&[2600]);
        assert_eq!(
            run(&once, 4).await,
            [
                Printed::Snapshot(ms(0), 1),
                Printed::Heartbeat(ms(1000), 1),
                Printed::Heartbeat(ms(2000), 1),
                Printed::Snapshot(ms(2600), 2),
                Printed::Heartbeat(ms(3600), 2),
            ]
        );

        // Constant change: one snapshot per request, requests at least 250 ms apart, no
        // heartbeats, and never the same snapshot twice.
        let busy = Scripted::new(Some(FollowMode::Pushed)).changing_every(ms(10));
        let lines = run(&busy, 2).await;
        assert!(
            busy.asked
                .borrow()
                .windows(2)
                .all(|w| w[1].at - w[0].at >= FOLLOW_MIN_INTERVAL)
        );
        assert!(lines.len() <= 9, "{lines:?}");
        let revisions: Vec<_> = lines
            .iter()
            .map(|line| match line {
                Printed::Snapshot(_, revision) => *revision,
                Printed::Heartbeat(..) => panic!("a heartbeat while changing: {lines:?}"),
            })
            .collect();
        assert!(revisions.windows(2).all(|w| w[1] > w[0]), "{lines:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn peer_follow_prints_the_same_lines_against_older_destinations_and_daemons() {
        // A ciao/peer/1 destination: this side polls once a second and compares.
        let old_destination = Scripted::new(Some(FollowMode::Polled)).changing_at(&[2600]);
        let expected = [
            Printed::Snapshot(ms(0), 1),
            Printed::Heartbeat(ms(1000), 1),
            Printed::Heartbeat(ms(2000), 1),
            Printed::Snapshot(ms(3000), 2),
            Printed::Heartbeat(ms(4000), 2),
        ];
        assert_eq!(run(&old_destination, 5).await, expected);

        // A daemon that does not know `follow` is asked once, then polled for snapshots.
        let old_daemon = Scripted::new(None).changing_at(&[2600]);
        assert_eq!(run(&old_daemon, 5).await, expected);
        let waits = old_daemon
            .asked
            .borrow()
            .iter()
            .filter(|a| a.wait.is_some())
            .count();
        assert_eq!(waits, 1);
        assert_eq!(old_daemon.polls.get(), 5);
        assert!(
            expected
                .windows(2)
                .all(|w| w[1].at() - w[0].at() >= FOLLOW_POLL_INTERVAL)
        );
    }

    /// A failed read ends the follow with that error; it is never shown as a heartbeat.
    struct Failing;

    impl FollowSource for Failing {
        async fn changed(
            &self,
            _: Option<SnapshotVersion>,
            _: Duration,
        ) -> Result<Option<FollowStep>> {
            bail!("daemon returned peer_unreachable")
        }

        async fn snapshot(&self) -> Result<Value> {
            bail!("daemon returned peer_unreachable")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_follow_reports_a_failed_read_as_an_error() {
        let mut printed = 0;
        let error = follow(&Failing, "s", Duration::from_secs(3), |_| {
            printed += 1;
            Ok(())
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("peer_unreachable"));
        assert_eq!(printed, 0);
    }
}
