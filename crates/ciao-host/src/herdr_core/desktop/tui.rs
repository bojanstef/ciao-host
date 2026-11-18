//! The TUI's public tab IDs are stable within a server. Bind confirmation to its socket too.
use super::Failure;
use crate::{
    host_protocol::herdr_management::{Action, TabParams, TuiInspection},
    workspace::{WorkspaceConfig, sanitize_tab_label},
};
use nix::unistd::Uid;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

fn incarnation(path: &Path) -> Result<String, Failure> {
    let info = std::fs::symlink_metadata(path).map_err(|_| Failure::Changed)?;
    if !info.file_type().is_socket() || info.uid() != Uid::effective().as_raw() {
        return Err(Failure::Changed);
    }
    let mut digest = Sha256::new();
    for n in [
        info.dev(),
        info.ino(),
        info.ctime() as u64,
        info.ctime_nsec() as u64,
    ] {
        digest.update(n.to_be_bytes());
    }
    Ok(format!("{:x}", digest.finalize())[..32].to_owned())
}

async fn socket(
    config: &WorkspaceConfig,
    session: &str,
    expected: Option<&str>,
) -> Result<(UnixStream, String), Failure> {
    let dir = if session == "default" {
        config.herdr_config.clone()
    } else {
        config.herdr_config.join("sessions").join(session)
    };
    let path = dir.join("herdr.sock");
    let instance = incarnation(&path)?;
    if expected.is_some_and(|s| s != instance) {
        return Err(Failure::Changed);
    }
    let stream = UnixStream::connect(&path)
        .await
        .map_err(|_| Failure::Changed)?;
    if stream.peer_cred().map_err(|_| Failure::Changed)?.uid() != Uid::effective().as_raw()
        || incarnation(&path)? != instance
    {
        return Err(Failure::Changed);
    }
    Ok((stream, instance))
}

async fn rpc(mut stream: UnixStream, method: &str, params: Value) -> Result<Value, Failure> {
    let mut bytes = serde_json::to_vec(&json!({"id":"ciao","method":method,"params":params}))
        .map_err(|_| Failure::Unavailable)?;
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| Failure::Unconfirmed)?;
    let mut line = Vec::new();
    BufReader::new(stream.take(super::super::RPC_BYTES as u64 + 1))
        .read_until(b'\n', &mut line)
        .await
        .map_err(|_| Failure::Unconfirmed)?;
    if line.len() > super::super::RPC_BYTES || !line.ends_with(b"\n") {
        return Err(Failure::Unconfirmed);
    }
    let mut response: Value = serde_json::from_slice(&line).map_err(|_| Failure::Unconfirmed)?;
    if response["id"] != "ciao" {
        return Err(Failure::Unconfirmed);
    }
    if let Some(error) = response.get("error") {
        return Err(match error["code"].as_str() {
            Some("confirmation_required") => Failure::ConfirmationRequired,
            Some("tab_not_found") => Failure::Changed,
            _ => Failure::Unconfirmed,
        });
    }
    response
        .get_mut("result")
        .map(Value::take)
        .ok_or(Failure::Unconfirmed)
}

pub(super) async fn inspect(config: &WorkspaceConfig, p: TuiInspection) -> Result<Value, Failure> {
    let (stream, instance) = socket(config, &p.session, None).await?;
    let result = rpc(stream, "tab.get", json!({"tab_id":p.tab}))
        .await
        .map_err(|failure| {
            if failure == Failure::Changed {
                failure
            } else {
                Failure::Unavailable
            }
        })?;
    if result["type"] != "tab_info" || result["tab"]["tab_id"] != p.tab {
        return Err(Failure::Changed);
    }
    let name = result["tab"]["label"]
        .as_str()
        .and_then(sanitize_tab_label)
        .unwrap_or(p.tab);
    Ok(json!({"instance":instance,"name":name}))
}

pub(super) async fn apply(config: &WorkspaceConfig, p: TabParams) -> Result<(), Failure> {
    let expected = p.instance.as_deref().ok_or(Failure::Changed)?;
    let (stream, _) = socket(config, &p.session, Some(expected)).await?;
    let (method, params) = match &p.action {
        Action::Close {} => ("tab.close", json!({"tab_id":p.tab})),
        Action::Rename { name } => ("tab.rename", json!({"tab_id":p.tab,"label":name})),
    };
    let result = rpc(stream, method, params).await?;
    let ok = match p.action {
        Action::Close {} => result["type"] == "ok",
        Action::Rename { name } => {
            result["type"] == "tab_info"
                && result["tab"]["tab_id"] == p.tab
                && result["tab"]["label"] == name
        }
    };
    if ok {
        Ok(())
    } else {
        Err(Failure::Unconfirmed)
    }
}
