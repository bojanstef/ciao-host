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
    peers::{Action, Admin, Descriptor, Outgoing},
};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Show this host's identity, incoming grants, outgoing links and selectable workspaces
    List,
    /// Allow one source host to launch agents in explicitly selected workspaces on this host
    Grant {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        name: String,
        #[arg(long, required = true)]
        workspace: Vec<String>,
    },
    /// Remember the destination link JSON returned by `peers grant` (or introduced by the phone)
    Remember {
        #[arg(long)]
        file: PathBuf,
    },
    /// Remove local incoming/outgoing access for an exact endpoint ID; running workers continue
    Revoke { endpoint: String },
    /// Ask a linked destination which of your granted workspaces are currently available
    Workspaces {
        #[arg(long)]
        host: String,
    },
    /// Start a managed Claude on a linked destination; reuse request-id to reconcile a lost reply
    Start {
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
    /// Poll a remote session for a bounded interval; each snapshot is one JSON line
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
            workspace,
        } => {
            json!({"op":"admin", "action":Admin::Grant { peer:Descriptor {endpoint_id:endpoint, name}, workspace_ids:workspace }})
        }
        Command::Remember { file } => {
            let link: Outgoing = serde_json::from_slice(&read_bounded(&file, 4096)?)?;
            json!({"op":"admin", "action":Admin::Remember {link}})
        }
        Command::Revoke { endpoint } => {
            json!({"op":"admin", "action":Admin::Revoke {endpoint_id:endpoint}})
        }
        Command::Workspaces { host } => {
            json!({"op":"call", "host":host, "action":Action::Workspaces {}})
        }
        Command::Start {
            host,
            workspace,
            request_id,
        } => {
            json!({"op":"call", "host":host, "action":Action::Start {request_id, workspace_id:workspace}})
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
            let until = tokio::time::Instant::now() + Duration::from_secs(seconds);
            loop {
                let value = ipc::request_peers(socket, json!({"op":"call", "host":host, "action":Action::Snapshot {session_id:session.clone()}})).await?;
                println!("{}", serde_json::to_string(&value)?);
                let next = tokio::time::Instant::now() + Duration::from_secs(1);
                if next >= until {
                    break;
                }
                tokio::time::sleep_until(next).await;
            }
            return Ok(());
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
