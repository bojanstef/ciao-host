use std::{collections::BTreeSet, io, path::Path, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    time::timeout,
};

use crate::protocol::PROTOCOL_VERSION;

pub const MAX_IPC_LINE: usize = 64 * 1024;
const IPC_TIMEOUT: Duration = Duration::from_secs(3);
/// Lifecycle verbs spawn a worker and digest-verify a large binary, so they get
/// a longer ceiling than the conversational status/pairing calls.
const IPC_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcRequest {
    pub v: u8,
    pub request_id: String,
    pub operation: IpcOperation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcOperation {
    Status,
    CreatePairing,
    PairingStatus {
        pairing_id: String,
    },
    AgentSessions,
    AgentStart {
        path: String,
    },
    AgentStop {
        session_id: String,
        expected_generation: u64,
    },
    AgentResume {
        session_id: String,
    },
    AgentRelease {
        session_id: String,
    },
    AgentPromote {
        session_id: String,
    },
    AgentForget {
        session_id: String,
    },
    Unpair {
        endpoint_id: String,
    },
}

/// Responses the CLI decodes from its own daemon are deliberately NOT `deny_unknown_fields`.
/// `ciao update` runs the *installed* CLI against the *newly installed* daemon, so the old
/// parser always meets the new payload — the one direction strictness cannot survive. A 0.1.11
/// host met `active_managed_workers` (added in 0.1.13), rejected the whole reply, and polled a
/// perfectly healthy daemon until its health check timed out and rolled the upgrade back. That
/// made every host below 0.1.13 permanently unable to update itself. Nothing was bought for it:
/// the daemon is the same product, same uid, on the other end of a 0600 socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub v: u8,
    pub daemon: String,
    pub iroh: String,
    pub host_endpoint_id: String,
    pub host_endpoint_id_short: String,
    pub paired_devices: usize,
    pub active_connections: Option<usize>,
    // Spec 004 §9.1: privacy-safe additive fields. Defaults keep a newer CLI compatible with
    // an older daemon during the update window.
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub protocol: Option<u8>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub active_terminals: Option<usize>,
    #[serde(default)]
    pub active_agent_sessions: Option<usize>,
    /// Live Ciao-owned workers only, reported apart from `active_agent_sessions` because the
    /// two carry different consequences. A restart stops a managed worker; it does not touch an
    /// attached session, whose agent runs in the operator's own terminal and merely reconnects.
    /// The installer's refusal needs the distinction, and the summed count cannot express it.
    #[serde(default)]
    pub active_managed_workers: Option<usize>,
    /// The subset of `active_terminals` whose work outlives a restart, because they are attached
    /// to a tmux or Herdr session that keeps running without Ciao. Reported inside that count
    /// rather than beside it: what is left after subtracting is the plain login shells, which are
    /// the only terminals a restart actually ends.
    #[serde(default)]
    pub resumable_terminals: Option<usize>,
    /// One short device ID per open terminal — the same prefix `ciao unpair` lists — so a count
    /// can be traced to the device holding it. Already-public identifiers, no names or paths.
    #[serde(default)]
    pub active_terminal_devices: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePairingResult {
    pub pairing_id: String,
    pub qr_uri: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("local IPC message exceeds {MAX_IPC_LINE} bytes")]
    Oversized,
    #[error("local IPC request is malformed: {0}")]
    Malformed(String),
    #[error("unsupported local IPC version")]
    UnsupportedVersion,
    #[error("unknown local IPC operation")]
    UnknownOperation,
    #[error("daemon returned {code}: {message}")]
    Daemon { code: String, message: String },
    // The source is not interpolated here: `#[from]` already exposes it, and anyhow prints the
    // chain, so including it would repeat the same text twice in one line.
    #[error("local IPC I/O failed")]
    Io(#[from] io::Error),
    #[error("timed out talking to the Ciao daemon")]
    Timeout,
}

impl IpcError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Oversized => "oversized",
            Self::Malformed(_) => "malformed_request",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnknownOperation => "unknown_operation",
            Self::Daemon { .. } => "daemon_error",
            Self::Io(_) => "io_error",
            Self::Timeout => "timeout",
        }
    }

    pub fn safe_message(&self) -> String {
        match self {
            Self::Malformed(_) => "Malformed local IPC request.".into(),
            Self::Daemon { message, .. } => message.clone(),
            _ => self.to_string(),
        }
    }
}

pub fn parse_request(line: &[u8]) -> Result<IpcRequest, IpcError> {
    if line.len() > MAX_IPC_LINE {
        return Err(IpcError::Oversized);
    }
    let value: Value =
        serde_json::from_slice(line).map_err(|error| IpcError::Malformed(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| IpcError::Malformed("request must be an object".into()))?;
    let version = object
        .get("v")
        .and_then(Value::as_u64)
        .ok_or_else(|| IpcError::Malformed("v must be an integer".into()))?;
    if version != u64::from(PROTOCOL_VERSION) {
        return Err(IpcError::UnsupportedVersion);
    }
    let request_id = object
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| IpcError::Malformed("request_id must be 1..128 characters".into()))?
        .to_owned();
    let operation = object
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| IpcError::Malformed("op must be a string".into()))?;

    let required: BTreeSet<&str> = match operation {
        "status" | "create_pairing" | "agent_sessions" => {
            ["v", "request_id", "op"].into_iter().collect()
        }
        "pairing_status" => ["v", "request_id", "op", "pairing_id"]
            .into_iter()
            .collect(),
        "agent_start" => ["v", "request_id", "op", "path"].into_iter().collect(),
        "agent_stop" => ["v", "request_id", "op", "session_id", "expected_generation"]
            .into_iter()
            .collect(),
        "agent_resume" | "agent_release" | "agent_promote" | "agent_forget" => {
            { ["v", "request_id", "op", "session_id"] }
                .into_iter()
                .collect()
        }
        "unpair" => ["v", "request_id", "op", "endpoint_id"]
            .into_iter()
            .collect(),
        _ => return Err(IpcError::UnknownOperation),
    };
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    if actual != required {
        return Err(IpcError::Malformed(
            "request contains missing or unknown fields".into(),
        ));
    }

    let session_id_field = |object: &serde_json::Map<String, Value>| {
        object
            .get("session_id")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 64
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
            .map(str::to_owned)
            .ok_or_else(|| IpcError::Malformed("invalid session_id".into()))
    };
    let operation = match operation {
        "status" => IpcOperation::Status,
        "create_pairing" => IpcOperation::CreatePairing,
        "pairing_status" => {
            let pairing_id = object
                .get("pairing_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 128)
                .ok_or_else(|| IpcError::Malformed("invalid pairing_id".into()))?;
            IpcOperation::PairingStatus {
                pairing_id: pairing_id.to_owned(),
            }
        }
        "agent_sessions" => IpcOperation::AgentSessions,
        "agent_start" => {
            let path = object
                .get("path")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 4096)
                .ok_or_else(|| IpcError::Malformed("invalid path".into()))?;
            IpcOperation::AgentStart {
                path: path.to_owned(),
            }
        }
        "agent_stop" => {
            let expected_generation = object
                .get("expected_generation")
                .and_then(Value::as_u64)
                .filter(|value| *value > 0)
                .ok_or_else(|| IpcError::Malformed("invalid expected_generation".into()))?;
            IpcOperation::AgentStop {
                session_id: session_id_field(object)?,
                expected_generation,
            }
        }
        "agent_resume" => IpcOperation::AgentResume {
            session_id: session_id_field(object)?,
        },
        "agent_promote" => IpcOperation::AgentPromote {
            session_id: session_id_field(object)?,
        },
        "agent_release" => IpcOperation::AgentRelease {
            session_id: session_id_field(object)?,
        },
        "agent_forget" => IpcOperation::AgentForget {
            session_id: session_id_field(object)?,
        },
        "unpair" => {
            let endpoint_id = object
                .get("endpoint_id")
                .and_then(Value::as_str)
                .ok_or_else(|| IpcError::Malformed("invalid endpoint_id".into()))?;
            // Deliberately the storage validator rather than a second copy of the same rule.
            crate::storage::validate_endpoint_id(endpoint_id)
                .map_err(|_| IpcError::Malformed("invalid endpoint_id".into()))?;
            IpcOperation::Unpair {
                endpoint_id: endpoint_id.to_owned(),
            }
        }
        _ => unreachable!("operation checked above"),
    };
    Ok(IpcRequest {
        v: PROTOCOL_VERSION,
        request_id,
        operation,
    })
}

pub fn success_response(request_id: &str, result: Value) -> Value {
    json!({
        "v": PROTOCOL_VERSION,
        "request_id": request_id,
        "ok": true,
        "result": result,
    })
}

pub fn error_response(request_id: &str, code: &str, message: &str) -> Value {
    json!({
        "v": PROTOCOL_VERSION,
        "request_id": request_id,
        "ok": false,
        "error": {
            "code": code,
            "message": message,
        },
    })
}

pub async fn read_bounded_line<R>(reader: &mut R) -> Result<Vec<u8>, IpcError>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if line.is_empty() {
                return Err(IpcError::Malformed("request ended before a line".into()));
            }
            break;
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |position| position + 1);
        if line.len().saturating_add(take) > MAX_IPC_LINE + 1 {
            return Err(IpcError::Oversized);
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            line.pop();
            break;
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.len() > MAX_IPC_LINE {
        return Err(IpcError::Oversized);
    }
    Ok(line)
}

pub async fn write_response(stream: &mut UnixStream, response: &Value) -> Result<(), IpcError> {
    let mut encoded =
        serde_json::to_vec(response).map_err(|error| IpcError::Malformed(error.to_string()))?;
    if encoded.len() > MAX_IPC_LINE {
        return Err(IpcError::Oversized);
    }
    encoded.push(b'\n');
    stream.write_all(&encoded).await?;
    // The short-lived client may close immediately after reading the newline. A resulting
    // ENOTCONN during our best-effort write-half shutdown does not invalidate the response.
    let _ = stream.shutdown().await;
    Ok(())
}

pub async fn send_request(path: &Path, operation: Value) -> Result<Value, IpcError> {
    send_request_within(path, operation, IPC_TIMEOUT).await
}

async fn send_request_within(
    path: &Path,
    operation: Value,
    ceiling: Duration,
) -> Result<Value, IpcError> {
    timeout(ceiling, send_request_inner(path, operation))
        .await
        .map_err(|_| IpcError::Timeout)?
}

async fn send_lifecycle_request(path: &Path, operation: Value) -> Result<Value, IpcError> {
    send_request_within(path, operation, IPC_LIFECYCLE_TIMEOUT).await
}

async fn send_request_inner(path: &Path, mut operation: Value) -> Result<Value, IpcError> {
    let request_id = format!("{:032x}", rand::random::<u128>());
    let object = operation
        .as_object_mut()
        .ok_or_else(|| IpcError::Malformed("operation must be an object".into()))?;
    object.insert("v".into(), json!(PROTOCOL_VERSION));
    object.insert("request_id".into(), json!(request_id));
    let mut encoded =
        serde_json::to_vec(&operation).map_err(|error| IpcError::Malformed(error.to_string()))?;
    if encoded.len() > MAX_IPC_LINE {
        return Err(IpcError::Oversized);
    }
    encoded.push(b'\n');

    let mut stream = UnixStream::connect(path).await?;
    stream.write_all(&encoded).await?;
    let mut reader = BufReader::new(stream);
    let response_bytes = read_bounded_line(&mut reader).await?;
    let response: Value = serde_json::from_slice(&response_bytes)
        .map_err(|error| IpcError::Malformed(error.to_string()))?;
    let object = response
        .as_object()
        .ok_or_else(|| IpcError::Malformed("response must be an object".into()))?;
    if object.get("v").and_then(Value::as_u64) != Some(u64::from(PROTOCOL_VERSION))
        || object.get("request_id").and_then(Value::as_str) != Some(request_id.as_str())
    {
        return Err(IpcError::Malformed(
            "response version or request_id mismatch".into(),
        ));
    }
    match object.get("ok").and_then(Value::as_bool) {
        Some(true) => object
            .get("result")
            .cloned()
            .ok_or_else(|| IpcError::Malformed("successful response has no result".into())),
        Some(false) => {
            let error: IpcErrorBody = serde_json::from_value(
                object
                    .get("error")
                    .cloned()
                    .ok_or_else(|| IpcError::Malformed("failed response has no error".into()))?,
            )
            .map_err(|error| IpcError::Malformed(error.to_string()))?;
            Err(IpcError::Daemon {
                code: error.code,
                message: error.message,
            })
        }
        None => Err(IpcError::Malformed("response has invalid ok field".into())),
    }
}

/// Revokes one paired device. `false` means it was already gone.
pub async fn request_unpair(path: &Path, endpoint_id: &str) -> Result<bool, IpcError> {
    let result = send_request(path, json!({ "op": "unpair", "endpoint_id": endpoint_id })).await?;
    result
        .get("removed")
        .and_then(Value::as_bool)
        .ok_or_else(|| IpcError::Malformed("unpair result has no removed field".into()))
}

pub async fn request_status(path: &Path) -> Result<DaemonStatus, IpcError> {
    let result = send_request(path, json!({ "op": "status" })).await?;
    serde_json::from_value(result).map_err(|error| IpcError::Malformed(error.to_string()))
}

pub async fn request_create_pairing(path: &Path) -> Result<CreatePairingResult, IpcError> {
    let result = send_request(path, json!({ "op": "create_pairing" })).await?;
    serde_json::from_value(result).map_err(|error| IpcError::Malformed(error.to_string()))
}

pub async fn request_pairing_status(path: &Path, pairing_id: &str) -> Result<Value, IpcError> {
    send_request(
        path,
        json!({ "op": "pairing_status", "pairing_id": pairing_id }),
    )
    .await
}

/// One bounded, privacy-safe row per managed session. Labels are the same
/// display class the paired phone already sees; no raw workspace path or
/// vendor session ID ever appears here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedSessionRow {
    pub session_id: String,
    pub presence: String,
    #[serde(default)]
    pub stored_reason: Option<String>,
    pub workspace_label: String,
    pub process_generation: u64,
    pub updated_at: u64,
    /// `managed` for a Ciao-owned worker, `attached` for a session running in the operator's
    /// own terminal. Attached rows exist so promotion has something to name.
    #[serde(default = "default_topology")]
    pub topology: String,
}

fn default_topology() -> String {
    "managed".into()
}

/// Categorical outcome of a managed lifecycle verb as the CLI displays it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleResult {
    pub state: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub process_generation: Option<u64>,
    #[serde(default)]
    pub reason_code: Option<String>,
    /// Release only: the vendor session ID to hand back. Local CLI use only —
    /// this is never sent to a paired device.
    #[serde(default)]
    pub vendor_session_id: Option<String>,
    /// Release only: the terminal session the conversation was handed back to.
    /// `None` when none could be created, which leaves the resume command as the
    /// only way back.
    #[serde(default)]
    pub handback_session: Option<String>,
}

pub async fn request_agent_sessions(path: &Path) -> Result<Vec<ManagedSessionRow>, IpcError> {
    let result = send_request(path, json!({ "op": "agent_sessions" })).await?;
    serde_json::from_value(result).map_err(|error| IpcError::Malformed(error.to_string()))
}

pub async fn request_agent_start(
    path: &Path,
    workspace_path: &str,
) -> Result<LifecycleResult, IpcError> {
    let result =
        send_lifecycle_request(path, json!({ "op": "agent_start", "path": workspace_path }))
            .await?;
    serde_json::from_value(result).map_err(|error| IpcError::Malformed(error.to_string()))
}

pub async fn request_agent_stop(
    path: &Path,
    session_id: &str,
    expected_generation: u64,
) -> Result<LifecycleResult, IpcError> {
    let result = send_lifecycle_request(
        path,
        json!({
            "op": "agent_stop",
            "session_id": session_id,
            "expected_generation": expected_generation,
        }),
    )
    .await?;
    serde_json::from_value(result).map_err(|error| IpcError::Malformed(error.to_string()))
}

pub async fn request_agent_resume(
    path: &Path,
    session_id: &str,
) -> Result<LifecycleResult, IpcError> {
    let result = send_lifecycle_request(
        path,
        json!({ "op": "agent_resume", "session_id": session_id }),
    )
    .await?;
    serde_json::from_value(result).map_err(|error| IpcError::Malformed(error.to_string()))
}

/// Drops a stored managed record. The conversation is untouched — the managed store is
/// metadata only, and Claude's own session store remains the transcript of record.
pub async fn request_agent_forget(
    path: &Path,
    session_id: &str,
) -> Result<LifecycleResult, IpcError> {
    let result = send_lifecycle_request(
        path,
        json!({ "op": "agent_forget", "session_id": session_id }),
    )
    .await?;
    serde_json::from_value(result).map_err(|error| IpcError::Malformed(error.to_string()))
}

pub async fn request_agent_promote(
    path: &Path,
    session_id: &str,
) -> Result<LifecycleResult, IpcError> {
    let result = send_lifecycle_request(
        path,
        json!({ "op": "agent_promote", "session_id": session_id }),
    )
    .await?;
    serde_json::from_value(result).map_err(|error| IpcError::Malformed(error.to_string()))
}

pub async fn request_agent_release(
    path: &Path,
    session_id: &str,
) -> Result<LifecycleResult, IpcError> {
    let result = send_lifecycle_request(
        path,
        json!({ "op": "agent_release", "session_id": session_id }),
    )
    .await?;
    serde_json::from_value(result).map_err(|error| IpcError::Malformed(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_version_operation_and_schema() {
        assert!(matches!(
            parse_request(br#"{"v":2,"request_id":"x","op":"status"}"#),
            Err(IpcError::UnsupportedVersion)
        ));
        assert!(matches!(
            parse_request(br#"{"v":1,"request_id":"x","op":"nope"}"#),
            Err(IpcError::UnknownOperation)
        ));
        assert!(matches!(
            parse_request(br#"{"v":1,"request_id":"x","op":"status","extra":1}"#),
            Err(IpcError::Malformed(_))
        ));
        assert_eq!(
            parse_request(br#"{"v":1,"request_id":"x","op":"status"}"#).unwrap(),
            IpcRequest {
                v: 1,
                request_id: "x".into(),
                operation: IpcOperation::Status,
            }
        );
    }

    #[test]
    fn managed_lifecycle_operations_parse_strictly() {
        assert_eq!(
            parse_request(br#"{"v":1,"request_id":"x","op":"agent_sessions"}"#)
                .unwrap()
                .operation,
            IpcOperation::AgentSessions
        );
        assert_eq!(
            parse_request(br#"{"v":1,"request_id":"x","op":"agent_start","path":"/tmp/w"}"#)
                .unwrap()
                .operation,
            IpcOperation::AgentStart {
                path: "/tmp/w".into()
            }
        );
        assert_eq!(
            parse_request(
                br#"{"v":1,"request_id":"x","op":"agent_stop","session_id":"abc-1","expected_generation":2}"#
            )
            .unwrap()
            .operation,
            IpcOperation::AgentStop {
                session_id: "abc-1".into(),
                expected_generation: 2,
            }
        );
        assert_eq!(
            parse_request(br#"{"v":1,"request_id":"x","op":"agent_resume","session_id":"abc-1"}"#)
                .unwrap()
                .operation,
            IpcOperation::AgentResume {
                session_id: "abc-1".into(),
            }
        );
        // Missing/zero fencing, hostile IDs, and unknown fields fail closed.
        assert!(matches!(
            parse_request(br#"{"v":1,"request_id":"x","op":"agent_stop","session_id":"abc-1"}"#),
            Err(IpcError::Malformed(_))
        ));
        assert!(matches!(
            parse_request(
                br#"{"v":1,"request_id":"x","op":"agent_stop","session_id":"abc-1","expected_generation":0}"#
            ),
            Err(IpcError::Malformed(_))
        ));
        assert!(matches!(
            parse_request(br#"{"v":1,"request_id":"x","op":"agent_resume","session_id":"../etc"}"#),
            Err(IpcError::Malformed(_))
        ));
        assert!(matches!(
            parse_request(br#"{"v":1,"request_id":"x","op":"agent_start","path":""}"#),
            Err(IpcError::Malformed(_))
        ));
        assert!(matches!(
            parse_request(
                br#"{"v":1,"request_id":"x","op":"agent_start","path":"/tmp/w","extra":1}"#
            ),
            Err(IpcError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn bounded_reader_rejects_oversized_line() {
        let data = vec![b'a'; MAX_IPC_LINE + 2];
        let mut reader = BufReader::new(data.as_slice());
        assert!(matches!(
            read_bounded_line(&mut reader).await,
            Err(IpcError::Oversized)
        ));
    }

    #[test]
    fn status_serialization_contains_no_secret_fields() {
        let status = DaemonStatus {
            v: 1,
            daemon: "running".into(),
            iroh: "online".into(),
            host_endpoint_id: "ab".repeat(32),
            host_endpoint_id_short: "ababababab".into(),
            paired_devices: 1,
            active_connections: Some(1),
            version: Some("0.1.0".into()),
            protocol: Some(1),
            platform: Some("macos".into()),
            active_terminals: Some(0),
            active_agent_sessions: Some(0),
            active_managed_workers: Some(0),
            resumable_terminals: Some(0),
            active_terminal_devices: Some(vec!["ababababab".into()]),
        };
        let encoded = serde_json::to_string(&status).unwrap();
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("capability"));
        assert!(!encoded.contains("ticket"));
        assert!(!encoded.contains("qr_uri"));
        // A machine name must never enter status output (Spec 004 §6.2).
        assert!(!encoded.contains("display_name"));
        assert!(!encoded.contains("hostname"));

        // A newer CLI still decodes an older daemon's status without the additive fields.
        let legacy = "{\"v\":1,\"daemon\":\"running\",\"iroh\":\"online\",\"host_endpoint_id\":\"ab\",\"host_endpoint_id_short\":\"ab\",\"paired_devices\":0,\"active_connections\":null}";
        let decoded: DaemonStatus = serde_json::from_str(legacy).unwrap();
        assert_eq!(decoded.version, None);
        assert_eq!(decoded.active_terminals, None);
        assert_eq!(decoded.active_agent_sessions, None);
        // An older daemon reports neither count, and absence must not read as work in
        // progress — otherwise the installer refuses forever during the update window.
        assert_eq!(decoded.active_managed_workers, None);
        assert_eq!(decoded.resumable_terminals, None);
        assert_eq!(decoded.active_terminal_devices, None);
        assert!(
            crate::install::refuse_if_active_work(
                decoded.active_terminals,
                decoded.resumable_terminals
            )
            .is_ok()
        );
    }

    /// The other direction, and the one that actually broke in the field. `ciao update` runs
    /// the *installed* CLI against the *newly installed* daemon, so this parser always meets
    /// the newer payload. A 0.1.11 host met `active_managed_workers`, rejected the entire
    /// reply, and polled a healthy daemon until its health check gave up and rolled the
    /// upgrade back — permanently, on every attempt.
    #[test]
    fn a_reply_from_a_newer_daemon_survives_fields_this_build_has_never_heard_of() {
        let newer = "{\"v\":1,\"daemon\":\"running\",\"iroh\":\"online\",\
                     \"host_endpoint_id\":\"ab\",\"host_endpoint_id_short\":\"ab\",\
                     \"paired_devices\":0,\"active_connections\":null,\"version\":\"9.9.9\",\
                     \"a_field_added_after_this_build\":42}";
        let decoded: DaemonStatus = serde_json::from_str(newer).expect(
            "an unknown field must not make the whole reply unreadable; that is an upgrade wall",
        );
        assert_eq!(decoded.version.as_deref(), Some("9.9.9"));
        assert_eq!(decoded.daemon, "running");
    }
}
