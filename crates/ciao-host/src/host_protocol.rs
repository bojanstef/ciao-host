use std::{collections::VecDeque, io, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

pub const HOST_ALPN: &[u8] = b"ciao/host/1";
pub const HOST_PROTOCOL_VERSION: u8 = 1;
pub const STREAM_KIND_RPC: u8 = 0x01;
pub const STREAM_KIND_TERMINAL: u8 = 0x02;
pub const STREAM_KIND_AGENT: u8 = 0x03;
// Stream kinds are allocated once, here, even for features that are not built yet (Spec 007
// §11.5): 0x04 is reserved for Spec 008 (git diff snapshot) and 0x06 for Spec 010 (terminal
// state sync). Neither is implemented — both bytes must keep decoding as unknown until their
// specs land, so do not add enum variants for them.
pub const STREAM_KIND_UPLOAD: u8 = 0x05;
/// Spec 015 file preview, host to phone. 0x07 rather than the next free byte because 0x06 is
/// still spoken for above.
pub const STREAM_KIND_DOWNLOAD: u8 = 0x07;
/// Loopback port forwarding, phone to host: one stream per TCP connection the app's own
/// loopback listener accepts, so a WebView on the phone can load a dev server bound to
/// `127.0.0.1` here. 0x08 is simply the next free byte.
pub const STREAM_KIND_FORWARD: u8 = 0x08;

pub const MAX_RPC_BODY: usize = 16 * 1024;
pub const MAX_OPEN_PAYLOAD: usize = 4 * 1024;
pub const MAX_OPENED_PAYLOAD: usize = 4 * 1024;
pub const MAX_EXIT_PAYLOAD: usize = 1024;
pub const MAX_ERROR_PAYLOAD: usize = 1024;
pub const MAX_DATA_PAYLOAD: usize = 16 * 1024;

pub const MAX_TERMINAL_STREAMS: u16 = 1;
pub const MAX_INCOMING_BIDI_STREAMS: u16 = 8;
/// Concurrent forward streams, held well under `MAX_INCOMING_BIDI_STREAMS` on purpose. A
/// browser opens up to six parallel connections per origin and QUIC makes an over-quota
/// `open_bi` *wait* rather than fail, so an uncapped forward would starve the terminal's own
/// stream and read as the terminal freezing. The app holds the same cap on its side, which is
/// the one that actually queues the browser; this is the fence behind it.
pub const MAX_FORWARD_STREAMS: usize = 3;
pub const MAX_INCOMING_UNI_STREAMS: u16 = 0;
pub const MAX_NORMAL_CONNECTIONS: usize = 16;
pub const MAX_NORMAL_CONNECTIONS_PER_ENDPOINT: usize = 2;
pub const MAX_PENDING_HANDSHAKES: usize = 32;
pub const MAX_ACTIVE_PTYS: usize = 8;
pub const MAX_ACTIVE_PTYS_PER_ENDPOINT: usize = 2;
pub const MAX_ACTIVE_AGENT_SUBSCRIPTIONS: usize = 16;
/// One live subscription per device (Spec 005 §11). Enforced by *superseding* the endpoint's
/// existing subscription rather than refusing the new one — see `try_add_superseding`. Kept as
/// the written statement of the bound; the grant path derives the behaviour from it.
///
/// This bounds *conversations*, not the directory. Listing every agent on every host is a
/// request/response `list` that takes no lease, which is why one open conversation never
/// limited what the home screen can show.
///
/// If directory push is built, this becomes a per-kind bound rather than a per-endpoint one:
/// a phone would hold a directory subscription *and* a conversation subscription, and under
/// today's rule opening a conversation would silently supersede the directory stream — the
/// live list going dead the moment you tapped into something being the exact failure this
/// enforcement style is otherwise designed to avoid.
pub const MAX_ACTIVE_AGENT_SUBSCRIPTIONS_PER_ENDPOINT: usize = 1;

pub const HOST_STREAM_RECEIVE_WINDOW: u32 = 128 * 1024;
pub const HOST_CONNECTION_RECEIVE_WINDOW: u32 = 512 * 1024;
pub const HOST_SEND_WINDOW: u64 = 512 * 1024;
pub const HOST_PENDING_INPUT_BYTES: usize = 64 * 1024;
pub const HOST_PENDING_OUTPUT_BYTES: usize = 256 * 1024;
pub const IOS_PENDING_INPUT_BYTES: usize = 64 * 1024;
pub const PASTE_MAX_BYTES: usize = 64 * 1024;
pub const SCROLLBACK_LINES: usize = 2_000;
pub const KITTY_IMAGE_CACHE_BYTES: usize = 8 * 1024 * 1024;

pub const STREAM_PREFACE_TIMEOUT: Duration = Duration::from_secs(5);
pub const HOST_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
pub const CLIENT_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

pub const MAX_SESSIONS_PER_PROVIDER: usize = 64;
/// Spec 021 §3.3: tabs are garnish on a session row. Twelve is more than a phone list can
/// usefully show, and the 16KB response bound needs a number it can reason about.
/// Raised from 12 on 2026-08-25. Twelve was sized for a herdr session whose tabs are the work
/// (three workspaces, seven tabs in the busy one). A herdr user who puts the project name on the
/// *workspace* instead runs thirty-five workspaces of two tabs each, and twelve cut that to a
/// meaningless prefix — six rows reading `claude`, `shell`, `claude`. 128 is that observed
/// ceiling with room, and `encode_snapshot_response_bounded` — which sheds *trailing tabs*, not
/// whole listings — is the bound that actually protects the frame. This one only keeps a
/// runaway provider from making the encoder do the whole job.
pub const MAX_TABS_PER_SESSION: usize = 128;
pub const MAX_TAB_ID_BYTES: usize = 64;
pub const MAX_TAB_LABEL_BYTES: usize = 64;
pub const MAX_TAB_STATUS_BYTES: usize = 16;
pub const MAX_SESSION_NAME_BYTES: usize = 64;
/// The hello advertises 16 as of `port.forward.v1`, so **the list is full**. A seventeenth is a
/// wire break in both directions — the app validates this same bound, so an over-long list fails
/// the whole hello rather than dropping a capability, and every app ever shipped enforces 16.
/// Raising it means raising it on both sides and shipping the host after the app. See
/// `docs/PROTOCOL.md` §5; `the_capability_is_advertised_and_the_hello_still_fits_its_bound`
/// fails first.
pub const MAX_CAPABILITY_ENTRIES: usize = 16;
pub const MAX_CAPABILITY_BYTES: usize = 64;
pub const MAX_PROVIDER_VERSION_BYTES: usize = 64;
pub const MAX_HOST_DISPLAY_NAME_BYTES: usize = 64;
pub const MAX_HOST_METADATA_TOKEN_BYTES: usize = 32;

pub const CAPABILITY_TERMINAL_SHELL: &str = "terminal.shell";
pub const CAPABILITY_HOST_INFO: &str = "host.info";
pub const CAPABILITY_WORKSPACE_SNAPSHOT: &str = "workspace.snapshot";
pub const CAPABILITY_TERMINAL_TMUX: &str = "terminal.tmux";
pub const CAPABILITY_TERMINAL_HERDR: &str = "terminal.herdr";
pub const CAPABILITY_AGENT_SESSION: &str = "agent.session.v1";
pub const CAPABILITY_AGENT_SESSION_MANAGED: &str = "agent.session.managed.v1";
pub const CAPABILITY_AGENT_SESSION_ADOPTED: &str = "agent.session.adopted.v1";
pub const CAPABILITY_TERMINAL_AGENT_ROUTE: &str = "terminal.agent_route.v1";
pub const CAPABILITY_NOTIFICATIONS_REGISTER: &str = "notifications.register";
/// Spec 018: an app-created, per-host ActivityKit instance whose opaque update token and
/// per-session opt-ins are registered over the already authorized host RPC.
pub const CAPABILITY_LIVE_ACTIVITY_REGISTER: &str = "live_activity.register";
pub const MAX_LIVE_ACTIVITY_SELECTIONS: usize = 8;
/// Spec 007 §4: the dedicated upload stream (`STREAM_KIND_UPLOAD`). Advertised so the app can
/// hide the attach affordance against a host that predates uploads.
pub const CAPABILITY_FILE_PUT: &str = "file.put.v1";
pub const CAPABILITY_FILE_GET: &str = "file.get.v1";
/// The host can dial one of its own loopback ports on a forward stream (`STREAM_KIND_FORWARD`),
/// so the app can draw a dev server running here. Advertised because a host that predates the
/// stream kind resets it, and a browser error page cannot explain a version skew — the app hides
/// "Open on Host" instead and leaves the link to the system browser, as it did before.
pub const CAPABILITY_PORT_FORWARD: &str = "port.forward.v1";
/// Spec 021: the host can enumerate multiplexer tabs into the workspace snapshot and honor a
/// tab focus hint on attach. Advertised so the app only asks hosts that understand the param —
/// an old app's snapshot decode fails closed on any unknown key, so emission is opt-in.
pub const CAPABILITY_WORKSPACE_TABS: &str = "workspace.tabs.v1";
/// The host can report the slash commands a terminal pane's agent would accept, so the phone
/// can offer them natively instead of leaving the composer to hide the TUI's own menu.
/// Advertised because a host that predates it answers `unsupported_method`, and the picker has
/// to be absent rather than empty-and-broken against one.
pub const CAPABILITY_TERMINAL_COMMANDS: &str = "terminal.commands.v1";

/// A push ticket is opaque here on purpose. The host carries it to the relay and never opens it;
/// only the relay that sealed it can. What is checked is the shape, at the trust boundary, so a
/// paired device cannot steer the relay request with anything but base64url text.
pub const MIN_PUSH_TICKET_BYTES: usize = 64;
pub const MAX_PUSH_TICKET_BYTES: usize = 512;

pub fn valid_push_ticket(value: &str) -> bool {
    (MIN_PUSH_TICKET_BYTES..=MAX_PUSH_TICKET_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub const PROVIDER_STATE_AVAILABLE: &str = "available";
pub const PROVIDER_STATE_NOT_INSTALLED: &str = "not_installed";
pub const PROVIDER_STATE_UNSUPPORTED_VERSION: &str = "unsupported_version";
pub const PROVIDER_STATE_ERROR: &str = "error";

/// Spec 003 §5.4: `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`, enforced identically in Rust and Swift.
pub fn valid_session_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_SESSION_NAME_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
}

/// Spec 021 §3.3: a tab id is provider-issued routing data that later rides back inside an
/// argv (`select-window -t`, `tab focus`), so its alphabet is pinned. tmux `@N` window ids and
/// herdr `wX:tN` ids both fit; shell metacharacters and separators never do.
pub fn valid_tab_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_TAB_ID_BYTES
        && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'@')
        // A bare `@` or an id of pure punctuation names nothing on either provider.
        && bytes.iter().any(u8::is_ascii_alphanumeric)
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b':' | b'.' | b'_' | b'-')
        })
}

/// Labels are display text the host has already sanitized (Spec 021 §4.3): bounded,
/// control-free UTF-8.
pub fn valid_tab_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= MAX_TAB_LABEL_BYTES && !label.chars().any(char::is_control)
}

/// `status` is an open set the app filters (`"working"` is the only rendered value), but its
/// shape is pinned so provider drift can add words without ever adding structure.
pub fn valid_tab_status(status: &str) -> bool {
    !status.is_empty()
        && status.len() <= MAX_TAB_STATUS_BYTES
        && status
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    Tmux,
    Herdr,
}

impl ProviderKind {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Tmux => "tmux",
            Self::Herdr => "herdr",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalTarget {
    Shell,
    TmuxAttach,
    TmuxCreate,
    HerdrAttach,
    HerdrCreate,
    AgentRoute,
}

impl TerminalTarget {
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "shell" => Some(Self::Shell),
            "tmux.attach" => Some(Self::TmuxAttach),
            "tmux.create" => Some(Self::TmuxCreate),
            "herdr.attach" => Some(Self::HerdrAttach),
            "herdr.create" => Some(Self::HerdrCreate),
            "agent_route" => Some(Self::AgentRoute),
            _ => None,
        }
    }

    pub const fn wire(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::TmuxAttach => "tmux.attach",
            Self::TmuxCreate => "tmux.create",
            Self::HerdrAttach => "herdr.attach",
            Self::HerdrCreate => "herdr.create",
            Self::AgentRoute => "agent_route",
        }
    }

    pub const fn provider(self) -> Option<ProviderKind> {
        match self {
            Self::Shell => None,
            Self::TmuxAttach | Self::TmuxCreate => Some(ProviderKind::Tmux),
            Self::HerdrAttach | Self::HerdrCreate => Some(ProviderKind::Herdr),
            Self::AgentRoute => None,
        }
    }

    pub const fn requires_session(self) -> bool {
        !matches!(self, Self::Shell)
    }
}

pub const CONNECTION_AUTHORIZATION_DENIED: u32 = 0x100;
pub const CONNECTION_PROTOCOL_VIOLATION: u32 = 0x101;
pub const CONNECTION_BUSY: u32 = 0x102;
pub const CONNECTION_SERVER_SHUTDOWN: u32 = 0x103;
/// Closes a same-installation connection displaced by a newer one (audit 2026-08-04 fix 2).
/// Its usual recipient is a suspension corpse that will never read it.
pub const CONNECTION_SUPERSEDED: u32 = 0x104;
pub const STREAM_CANCELLED: u32 = 0x200;
pub const STREAM_MALFORMED: u32 = 0x201;
pub const STREAM_FRAME_TOO_LARGE: u32 = 0x202;
pub const STREAM_UNEXPECTED: u32 = 0x203;
pub const STREAM_TERMINAL_LIMIT: u32 = 0x204;
pub const STREAM_PTY_FAILURE: u32 = 0x205;
pub const STREAM_BACKPRESSURE: u32 = 0x206;
pub const STREAM_INTERNAL: u32 = 0x207;
/// More forward streams than `MAX_FORWARD_STREAMS` allows on one connection.
pub const STREAM_FORWARD_LIMIT: u32 = 0x208;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Rpc,
    Terminal,
    Agent,
    Upload,
    Download,
    Forward,
}

impl StreamKind {
    pub const fn byte(self) -> u8 {
        match self {
            Self::Rpc => STREAM_KIND_RPC,
            Self::Terminal => STREAM_KIND_TERMINAL,
            Self::Agent => STREAM_KIND_AGENT,
            Self::Upload => STREAM_KIND_UPLOAD,
            Self::Download => STREAM_KIND_DOWNLOAD,
            Self::Forward => STREAM_KIND_FORWARD,
        }
    }

    pub fn from_byte(value: u8) -> Result<Self, HostProtocolError> {
        match value {
            STREAM_KIND_RPC => Ok(Self::Rpc),
            STREAM_KIND_TERMINAL => Ok(Self::Terminal),
            STREAM_KIND_AGENT => Ok(Self::Agent),
            STREAM_KIND_UPLOAD => Ok(Self::Upload),
            STREAM_KIND_DOWNLOAD => Ok(Self::Download),
            STREAM_KIND_FORWARD => Ok(Self::Forward),
            _ => Err(HostProtocolError::UnknownStreamKind),
        }
    }
}

#[derive(Debug, Error)]
pub enum HostProtocolError {
    #[error("stream ended while reading a protocol value")]
    Truncated,
    #[error("unsupported host protocol version")]
    UnsupportedVersion,
    #[error("unknown host stream kind")]
    UnknownStreamKind,
    #[error("stream preface timed out")]
    PrefaceTimeout,
    #[error("payload cannot be empty")]
    ZeroLength,
    #[error("payload exceeds its frame-type limit")]
    FrameTooLarge,
    #[error("payload contains malformed JSON")]
    MalformedJson,
    #[error("request ID is invalid")]
    InvalidRequestId,
    #[error("host RPC method is unsupported")]
    UnsupportedMethod,
    #[error("terminal dimensions are invalid")]
    InvalidDimensions,
    #[error("terminal target is unsupported")]
    UnsupportedTarget,
    #[error("terminal session target is invalid")]
    InvalidTarget,
    #[error("terminal identifier is invalid")]
    InvalidTerminalId,
    #[error("terminal control value is invalid")]
    InvalidControlValue,
    #[error("terminal frame type is unknown")]
    UnknownFrameType,
    #[error("terminal frame direction is invalid")]
    UnexpectedDirection,
    #[error("protocol message order is invalid")]
    UnexpectedOrder,
    #[error("stream I/O failed: {0}")]
    Io(#[from] io::Error),
}

pub fn encode_stream_preface(kind: StreamKind) -> [u8; 2] {
    [HOST_PROTOCOL_VERSION, kind.byte()]
}

pub fn decode_stream_preface(bytes: [u8; 2]) -> Result<StreamKind, HostProtocolError> {
    if bytes[0] != HOST_PROTOCOL_VERSION {
        return Err(HostProtocolError::UnsupportedVersion);
    }
    StreamKind::from_byte(bytes[1])
}

pub async fn read_stream_preface<R>(reader: &mut R) -> Result<StreamKind, HostProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0_u8; 2];
    read_exact(reader, &mut bytes).await?;
    decode_stream_preface(bytes)
}

pub async fn read_stream_preface_with_timeout<R>(
    reader: &mut R,
    duration: Duration,
) -> Result<StreamKind, HostProtocolError>
where
    R: AsyncRead + Unpin,
{
    timeout(duration, read_stream_preface(reader))
        .await
        .map_err(|_| HostProtocolError::PrefaceTimeout)?
}

pub async fn write_stream_preface<W>(
    writer: &mut W,
    kind: StreamKind,
) -> Result<(), HostProtocolError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&encode_stream_preface(kind)).await?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHelloParams {
    pub min_protocol: u16,
    pub max_protocol: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHelloRequest {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub method: String,
    pub params: HostHelloParams,
}

impl HostHelloRequest {
    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION
            || self.params.min_protocol > u16::from(HOST_PROTOCOL_VERSION)
            || self.params.max_protocol < u16::from(HOST_PROTOCOL_VERSION)
            || self.params.min_protocol > self.params.max_protocol
        {
            return Err(HostProtocolError::UnsupportedVersion);
        }
        if self.message_type != "request" {
            return Err(HostProtocolError::UnexpectedOrder);
        }
        validate_request_id(&self.request_id)?;
        if self.method != "host.hello" {
            return Err(HostProtocolError::UnsupportedMethod);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLimits {
    pub max_terminal_streams: u16,
    pub max_frame_payload_bytes: u32,
    pub max_cols: u16,
    pub max_rows: u16,
    pub max_pixel_width: u16,
    pub max_pixel_height: u16,
}

impl Default for HostLimits {
    fn default() -> Self {
        Self {
            max_terminal_streams: MAX_TERMINAL_STREAMS,
            max_frame_payload_bytes: MAX_DATA_PAYLOAD as u32,
            max_cols: Dimensions::MAX_COLS,
            max_rows: Dimensions::MAX_ROWS,
            max_pixel_width: Dimensions::MAX_PIXEL,
            max_pixel_height: Dimensions::MAX_PIXEL,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHelloResult {
    pub selected_protocol: u16,
    pub host_endpoint_id: String,
    pub installation_endpoint_id: String,
    pub capabilities: Vec<String>,
    pub limits: HostLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHelloResponse {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub result: HostHelloResult,
}

impl HostHelloResponse {
    pub fn new(
        request_id: String,
        host_endpoint_id: String,
        installation_endpoint_id: String,
    ) -> Self {
        Self {
            v: HOST_PROTOCOL_VERSION,
            message_type: "response".into(),
            request_id,
            result: HostHelloResult {
                selected_protocol: u16::from(HOST_PROTOCOL_VERSION),
                host_endpoint_id,
                installation_endpoint_id,
                capabilities: vec![
                    CAPABILITY_TERMINAL_SHELL.into(),
                    CAPABILITY_HOST_INFO.into(),
                    CAPABILITY_WORKSPACE_SNAPSHOT.into(),
                    CAPABILITY_TERMINAL_TMUX.into(),
                    CAPABILITY_TERMINAL_HERDR.into(),
                    CAPABILITY_AGENT_SESSION.into(),
                    CAPABILITY_AGENT_SESSION_MANAGED.into(),
                    CAPABILITY_AGENT_SESSION_ADOPTED.into(),
                    CAPABILITY_TERMINAL_AGENT_ROUTE.into(),
                    CAPABILITY_NOTIFICATIONS_REGISTER.into(),
                    CAPABILITY_LIVE_ACTIVITY_REGISTER.into(),
                    CAPABILITY_FILE_PUT.into(),
                    CAPABILITY_FILE_GET.into(),
                    CAPABILITY_PORT_FORWARD.into(),
                    CAPABILITY_WORKSPACE_TABS.into(),
                    CAPABILITY_TERMINAL_COMMANDS.into(),
                ],
                limits: HostLimits::default(),
            },
        }
    }

    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION
            || self.message_type != "response"
            || self.result.selected_protocol != u16::from(HOST_PROTOCOL_VERSION)
        {
            return Err(HostProtocolError::InvalidControlValue);
        }
        validate_capabilities(&self.result.capabilities)?;
        validate_request_id(&self.request_id)?;
        validate_endpoint_id_text(&self.result.host_endpoint_id)?;
        validate_endpoint_id_text(&self.result.installation_endpoint_id)?;
        if self.result.limits.max_terminal_streams == 0
            || self.result.limits.max_frame_payload_bytes == 0
            || self.result.limits.max_cols < Dimensions::MIN_COLS
            || self.result.limits.max_rows < Dimensions::MIN_ROWS
        {
            return Err(HostProtocolError::InvalidControlValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcErrorResponse {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: Option<String>,
    pub error: RpcErrorBody,
}

impl RpcErrorResponse {
    pub fn new(request_id: Option<String>, code: &str, message: &str) -> Self {
        Self {
            v: HOST_PROTOCOL_VERSION,
            message_type: "error".into(),
            request_id,
            error: RpcErrorBody {
                code: code.into(),
                message: message.into(),
            },
        }
    }

    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION || self.message_type != "error" {
            return Err(HostProtocolError::InvalidControlValue);
        }
        if let Some(request_id) = &self.request_id {
            validate_request_id(request_id)?;
        }
        validate_code_and_message(&self.error.code, &self.error.message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcResponse {
    Hello(HostHelloResponse),
    Error(RpcErrorResponse),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotParams {
    /// Spec 021 §3.2: the app asks for tabs only when the hello advertised
    /// `workspace.tabs.v1`. Old apps send `{}`, this decodes false, and the response stays
    /// byte-identical to the pre-tabs protocol their strict codec requires.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tabs: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Which pane the phone wants a command list for, named the way it named the pane when it
/// opened the terminal.
///
/// Deliberately not a directory. The phone knows the pane's directory — the snapshot told it —
/// but a path from a phone is a path the host would then run a CLI in, and the host has no way
/// to tell one the user is standing in from one they are not. These two values are provider
/// vocabulary the host itself issued, so the host resolves the directory the same way file
/// preview does, and the phone never gets to choose where anything runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalCommandsParams {
    pub target: String,
    pub session: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalCommandsRequest {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub method: String,
    pub params: TerminalCommandsParams,
}

impl TerminalCommandsRequest {
    pub fn new(request_id: String, target: TerminalTarget, session: String) -> Self {
        Self {
            v: HOST_PROTOCOL_VERSION,
            message_type: "request".into(),
            request_id,
            method: CAPABILITY_TERMINAL_COMMANDS.into(),
            params: TerminalCommandsParams {
                target: target.wire().into(),
                session,
            },
        }
    }

    /// The provider this pane belongs to, or a refusal. A target with no provider — a plain
    /// shell, an agent route — has no multiplexer to ask, so it is refused here rather than
    /// answered with an empty list that would read as "this pane has no commands".
    pub fn validated_provider(&self) -> Result<ProviderKind, HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION {
            return Err(HostProtocolError::UnsupportedVersion);
        }
        if self.message_type != "request" || self.method != CAPABILITY_TERMINAL_COMMANDS {
            return Err(HostProtocolError::InvalidControlValue);
        }
        validate_request_id(&self.request_id)?;
        if !valid_session_name(&self.params.session) {
            return Err(HostProtocolError::InvalidControlValue);
        }
        TerminalTarget::from_wire(&self.params.target)
            .ok_or(HostProtocolError::UnsupportedTarget)?
            .provider()
            .ok_or(HostProtocolError::UnsupportedTarget)
    }

    pub fn validate(&self) -> Result<(), HostProtocolError> {
        self.validated_provider()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalCommandsResult {
    /// Empty whenever the host cannot vouch for a list: no agent in the pane, an agent that is
    /// not Claude, no managed runtime installed, a probe that failed. The phone shows no picker
    /// for all of them, because none of them is a pane where a guessed command would land.
    pub commands: Vec<crate::slash_commands::SlashCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalCommandsResponse {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub result: TerminalCommandsResult,
}

impl TerminalCommandsResponse {
    pub fn new(request_id: String, commands: Vec<crate::slash_commands::SlashCommand>) -> Self {
        Self {
            v: HOST_PROTOCOL_VERSION,
            message_type: "response".into(),
            request_id,
            result: TerminalCommandsResult { commands },
        }
    }

    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION || self.message_type != "response" {
            return Err(HostProtocolError::InvalidControlValue);
        }
        validate_request_id(&self.request_id)?;
        validate_slash_commands(&self.result.commands)
    }
}

/// The same bounds the host applied when it built the list, checked again at the wire. A phone
/// decoding this runs the identical check, so neither side is trusting the other's arithmetic.
pub fn validate_slash_commands(
    commands: &[crate::slash_commands::SlashCommand],
) -> Result<(), HostProtocolError> {
    if commands.len() > crate::slash_commands::MAX_SLASH_COMMANDS {
        return Err(HostProtocolError::InvalidControlValue);
    }
    for command in commands {
        if command.name.is_empty()
            || command.name.len() > crate::slash_commands::MAX_COMMAND_NAME_BYTES
            || command.hint.len() > crate::slash_commands::MAX_COMMAND_HINT_BYTES
            || command.description.len() > crate::slash_commands::MAX_COMMAND_DESCRIPTION_BYTES
        {
            return Err(HostProtocolError::InvalidControlValue);
        }
        // A name becomes a row, gains a slash, and is typed into a terminal. Whitespace and
        // control bytes have no business making that trip.
        if !command
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
        {
            return Err(HostProtocolError::InvalidControlValue);
        }
        // An alias is typed exactly like a name, so it is held to the name's rule. Nothing here
        // relaxes because the field is optional.
        if command.aliases.len() > crate::slash_commands::MAX_COMMAND_ALIASES {
            return Err(HostProtocolError::InvalidControlValue);
        }
        for alias in &command.aliases {
            if alias.is_empty()
                || alias.len() > crate::slash_commands::MAX_COMMAND_NAME_BYTES
                || !alias.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.')
                })
            {
                return Err(HostProtocolError::InvalidControlValue);
            }
        }
        if command
            .hint
            .bytes()
            .chain(command.description.bytes())
            .any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(HostProtocolError::InvalidControlValue);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotRequest {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub method: String,
    pub params: WorkspaceSnapshotParams,
}

impl WorkspaceSnapshotRequest {
    pub fn new(request_id: String) -> Self {
        Self {
            v: HOST_PROTOCOL_VERSION,
            message_type: "request".into(),
            request_id,
            method: "workspace.snapshot".into(),
            params: WorkspaceSnapshotParams::default(),
        }
    }

    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION {
            return Err(HostProtocolError::UnsupportedVersion);
        }
        if self.message_type != "request" {
            return Err(HostProtocolError::UnexpectedOrder);
        }
        validate_request_id(&self.request_id)?;
        if self.method != "workspace.snapshot" {
            return Err(HostProtocolError::UnsupportedMethod);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInfoParams {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInfoRequest {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub method: String,
    pub params: HostInfoParams,
}

impl HostInfoRequest {
    pub fn new(request_id: String) -> Self {
        Self {
            v: HOST_PROTOCOL_VERSION,
            message_type: "request".into(),
            request_id,
            method: "host.info".into(),
            params: HostInfoParams {},
        }
    }

    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION {
            return Err(HostProtocolError::UnsupportedVersion);
        }
        if self.message_type != "request" {
            return Err(HostProtocolError::UnexpectedOrder);
        }
        validate_request_id(&self.request_id)?;
        if self.method != "host.info" {
            return Err(HostProtocolError::UnsupportedMethod);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInfoResult {
    pub v: u8,
    pub display_name: String,
    pub platform: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution_version: Option<String>,
    pub architecture: String,
    /// Stable opaque machine identity (hashed, never the raw machine id) that survives
    /// `ciao reset`, letting the app forget a re-paired machine's dead previous identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_token: Option<String>,
    /// The host's own `ciao` version, so a report from the app can name the build that produced
    /// it. Optional on the wire because a host predating this field sends nothing, which is also
    /// why `HOST_PROTOCOL_VERSION` is deliberately not bumped: an additive optional field the
    /// decoders already tolerate, versus a bump that would make every current host read as
    /// unsupported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl HostInfoResult {
    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION
            || !valid_host_display_name(&self.display_name)
            || !matches!(self.platform.as_str(), "macos" | "linux")
            || !matches!(self.architecture.as_str(), "aarch64" | "x86_64")
            || self
                .distribution
                .as_deref()
                .is_some_and(|value| !valid_host_metadata_token(value))
            || self
                .distribution_version
                .as_deref()
                .is_some_and(|value| !valid_host_metadata_token(value))
            || self
                .machine_token
                .as_deref()
                .is_some_and(|value| !valid_machine_token(value))
            || self
                .version
                .as_deref()
                .is_some_and(|value| !valid_host_metadata_token(value))
            || (self.platform == "macos"
                && (self.distribution.is_some() || self.distribution_version.is_some()))
        {
            return Err(HostProtocolError::InvalidControlValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInfoResponse {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub result: HostInfoResult,
}

impl HostInfoResponse {
    pub fn new(request_id: String, result: HostInfoResult) -> Self {
        Self {
            v: HOST_PROTOCOL_VERSION,
            message_type: "response".into(),
            request_id,
            result,
        }
    }

    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION || self.message_type != "response" {
            return Err(HostProtocolError::InvalidControlValue);
        }
        validate_request_id(&self.request_id)?;
        self.result.validate()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationsRegisterParams {
    /// The relay ticket this host may push to. Absent revokes: the phone is telling this host to
    /// stop being able to reach it, which is what unpairing from the app side amounts to when
    /// the connection is still up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationsRegisterRequest {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub method: String,
    pub params: NotificationsRegisterParams,
}

impl NotificationsRegisterRequest {
    pub fn new(request_id: String, ticket: Option<String>) -> Self {
        Self {
            v: HOST_PROTOCOL_VERSION,
            message_type: "request".into(),
            request_id,
            method: CAPABILITY_NOTIFICATIONS_REGISTER.into(),
            params: NotificationsRegisterParams { ticket },
        }
    }

    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION {
            return Err(HostProtocolError::UnsupportedVersion);
        }
        if self.message_type != "request" {
            return Err(HostProtocolError::UnexpectedOrder);
        }
        validate_request_id(&self.request_id)?;
        if self.method != CAPABILITY_NOTIFICATIONS_REGISTER {
            return Err(HostProtocolError::UnsupportedMethod);
        }
        if self
            .params
            .ticket
            .as_deref()
            .is_some_and(|ticket| !valid_push_ticket(ticket))
        {
            return Err(HostProtocolError::InvalidControlValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationsRegisterResult {
    pub v: u8,
    /// True while this host holds a ticket, so the phone can tell "stored" from "revoked"
    /// without the host ever echoing the ticket back.
    pub registered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationsRegisterResponse {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub result: NotificationsRegisterResult,
}

impl NotificationsRegisterResponse {
    pub fn new(request_id: String, registered: bool) -> Self {
        Self {
            v: HOST_PROTOCOL_VERSION,
            message_type: "response".into(),
            request_id,
            result: NotificationsRegisterResult {
                v: HOST_PROTOCOL_VERSION,
                registered,
            },
        }
    }

    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION
            || self.message_type != "response"
            || self.result.v != HOST_PROTOCOL_VERSION
        {
            return Err(HostProtocolError::InvalidControlValue);
        }
        validate_request_id(&self.request_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveActivitySelectionMutation {
    pub session_id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveActivityRegisterParams {
    /// The relay's opaque handle on this ActivityKit instance's push-update token. Absent clears
    /// the registration and every selection; present with no mutation rotates only the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    /// One explicit add/remove. Sending the whole selected set would make a stale app snapshot
    /// erase an opt-in the host already holds; mutations make concurrent retries idempotent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<LiveActivitySelectionMutation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveActivityRegisterRequest {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub method: String,
    pub params: LiveActivityRegisterParams,
}

impl LiveActivityRegisterRequest {
    pub fn new(
        request_id: String,
        ticket: Option<String>,
        selection: Option<LiveActivitySelectionMutation>,
    ) -> Self {
        Self {
            v: HOST_PROTOCOL_VERSION,
            message_type: "request".into(),
            request_id,
            method: CAPABILITY_LIVE_ACTIVITY_REGISTER.into(),
            params: LiveActivityRegisterParams { ticket, selection },
        }
    }

    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION {
            return Err(HostProtocolError::UnsupportedVersion);
        }
        if self.message_type != "request" {
            return Err(HostProtocolError::UnexpectedOrder);
        }
        validate_request_id(&self.request_id)?;
        if self.method != CAPABILITY_LIVE_ACTIVITY_REGISTER {
            return Err(HostProtocolError::UnsupportedMethod);
        }
        if self
            .params
            .ticket
            .as_deref()
            .is_some_and(|ticket| !valid_push_ticket(ticket))
            || (self.params.ticket.is_none() && self.params.selection.is_some())
            || self
                .params
                .selection
                .as_ref()
                .is_some_and(|selection| !valid_live_activity_session_id(&selection.session_id))
        {
            return Err(HostProtocolError::InvalidControlValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveActivityRegisterResult {
    pub v: u8,
    pub registered: bool,
    pub selected_sessions: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveActivityRegisterResponse {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub result: LiveActivityRegisterResult,
}

impl LiveActivityRegisterResponse {
    pub fn new(request_id: String, selected_sessions: usize) -> Self {
        Self {
            v: HOST_PROTOCOL_VERSION,
            message_type: "response".into(),
            request_id,
            result: LiveActivityRegisterResult {
                v: HOST_PROTOCOL_VERSION,
                registered: selected_sessions > 0,
                selected_sessions: u8::try_from(selected_sessions).unwrap_or(u8::MAX),
            },
        }
    }

    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION
            || self.message_type != "response"
            || self.result.v != HOST_PROTOCOL_VERSION
            || usize::from(self.result.selected_sessions) > MAX_LIVE_ACTIVITY_SELECTIONS
            || self.result.registered != (self.result.selected_sessions > 0)
        {
            return Err(HostProtocolError::InvalidControlValue);
        }
        validate_request_id(&self.request_id)
    }
}

pub fn valid_live_activity_session_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcRequest {
    Hello(HostHelloRequest),
    HostInfo(HostInfoRequest),
    WorkspaceSnapshot(WorkspaceSnapshotRequest),
    NotificationsRegister(NotificationsRegisterRequest),
    LiveActivityRegister(LiveActivityRegisterRequest),
    TerminalCommands(TerminalCommandsRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationsRpcResponse {
    Registered(NotificationsRegisterResponse),
    Error(RpcErrorResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveActivityRpcResponse {
    Registered(LiveActivityRegisterResponse),
    Error(RpcErrorResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostInfoRpcResponse {
    Info(HostInfoResponse),
    Error(RpcErrorResponse),
}

/// Spec 021 §3.3: one shared tab shape for both providers. `id` is the provider's stable
/// routing handle (`@N` tmux window id, `wX:tN` herdr tab id), `label` is sanitized display
/// text, and `status` is herdr's per-tab agent state carried verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTabEntry {
    pub id: String,
    pub label: String,
    pub focused: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// The Agent Session this tab holds, when the host has a live route proving one is there.
    ///
    /// Deliberately not capability-gated. Spec 021 §7.1 already made a tab's unknown keys
    /// ignorable on both sides so the garnish could grow without breaking a phone that predates
    /// it, and this is that growth: an older app skips the field, a newer app against an older
    /// host never sees one, and neither direction changes a byte it already understood.
    ///
    /// It is an opaque Ciao session ID — the same one the Agents list keys on — and never a
    /// vendor ID, path, or route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_session_id: Option<String>,
    /// The herdr workspace this tab lives in, as its **label** and never its id — the id is
    /// already the tab id's prefix, and a group header reading `w9` names nothing.
    ///
    /// herdr's own model is session → workspace → tab, and `herdr tab list` returns every tab
    /// in the session flattened across workspaces. Which level carries the meaning is the
    /// user's choice, not herdr's: name your tabs and the flat list reads fine, name your
    /// workspaces and it reads as `claude, shell, claude, shell`. Carrying the label lets the
    /// app draw the level herdr actually has.
    ///
    /// Absent on tmux (no such level), absent when the session has one workspace (a header
    /// repeated over every row is not information), and absent from any host predating this —
    /// the same ignorable-garnish growth `agent_session_id` took.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
}

/// Which live pane holds which Agent Session, keyed as a workspace tab row names itself:
/// provider, session name, tab id. Built by the session supervisor, consumed by the snapshot
/// builder; see `AgentRouteProof::tab_key`.
pub type AgentTabIndex = std::collections::HashMap<(ProviderKind, String, String), String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TmuxSessionEntry {
    pub name: String,
    pub attached: bool,
    pub windows: u32,
    pub created_unix: u64,
    /// Present only when the snapshot request asked for tabs (Spec 021 §3.2) and the windows
    /// were enumerable; never an empty list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tabs: Option<Vec<SessionTabEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HerdrSessionEntry {
    pub name: String,
    pub running: bool,
    pub is_default: bool,
    /// Same contract as the tmux field; additionally absent for any session not running,
    /// since a stopped herdr has no socket to ask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tabs: Option<Vec<SessionTabEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TmuxProviderSnapshot {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<TmuxSessionEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HerdrProviderSnapshot {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<HerdrSessionEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceProviders {
    pub tmux: TmuxProviderSnapshot,
    pub herdr: HerdrProviderSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotResult {
    pub v: u8,
    pub providers: WorkspaceProviders,
    pub omitted_sessions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotResponse {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub result: WorkspaceSnapshotResult,
}

fn validate_provider_state(state: &str) -> Result<(), HostProtocolError> {
    match state {
        PROVIDER_STATE_AVAILABLE
        | PROVIDER_STATE_NOT_INSTALLED
        | PROVIDER_STATE_UNSUPPORTED_VERSION
        | PROVIDER_STATE_ERROR => Ok(()),
        _ => Err(HostProtocolError::InvalidControlValue),
    }
}

fn validate_provider_version(version: Option<&str>) -> Result<(), HostProtocolError> {
    let Some(version) = version else {
        return Ok(());
    };
    if version.is_empty()
        || version.len() > MAX_PROVIDER_VERSION_BYTES
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(HostProtocolError::InvalidControlValue);
    }
    Ok(())
}

fn validate_provider_shape<T>(
    state: &str,
    version: Option<&str>,
    sessions: Option<&[T]>,
    session_name: impl Fn(&T) -> &str,
    session_tabs: impl Fn(&T) -> Option<&[SessionTabEntry]>,
) -> Result<(), HostProtocolError> {
    validate_provider_state(state)?;
    validate_provider_version(version)?;
    match sessions {
        Some(sessions) if state == PROVIDER_STATE_AVAILABLE => {
            if sessions.len() > MAX_SESSIONS_PER_PROVIDER {
                return Err(HostProtocolError::InvalidControlValue);
            }
            for session in sessions {
                if !valid_session_name(session_name(session)) {
                    return Err(HostProtocolError::InvalidControlValue);
                }
                if let Some(tabs) = session_tabs(session) {
                    validate_session_tabs(tabs)?;
                }
            }
            Ok(())
        }
        None if state != PROVIDER_STATE_AVAILABLE => Ok(()),
        _ => Err(HostProtocolError::InvalidControlValue),
    }
}

/// Spec 021 §3.3. An empty list is refused on purpose: "no tabs" is spelled by omitting the
/// field, so there is exactly one wire shape per meaning.
fn validate_session_tabs(tabs: &[SessionTabEntry]) -> Result<(), HostProtocolError> {
    if tabs.is_empty()
        || tabs.len() > MAX_TABS_PER_SESSION
        || tabs.iter().filter(|tab| tab.focused).count() > 1
    {
        return Err(HostProtocolError::InvalidControlValue);
    }
    for tab in tabs {
        if !valid_tab_id(&tab.id)
            || !valid_tab_label(&tab.label)
            || !tab.status.as_deref().is_none_or(valid_tab_status)
            || !tab.workspace.as_deref().is_none_or(valid_tab_label)
        {
            return Err(HostProtocolError::InvalidControlValue);
        }
    }
    Ok(())
}

impl WorkspaceSnapshotResult {
    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION {
            return Err(HostProtocolError::UnsupportedVersion);
        }
        validate_provider_shape(
            &self.providers.tmux.state,
            self.providers.tmux.version.as_deref(),
            self.providers.tmux.sessions.as_deref(),
            |session: &TmuxSessionEntry| session.name.as_str(),
            |session: &TmuxSessionEntry| session.tabs.as_deref(),
        )?;
        validate_provider_shape(
            &self.providers.herdr.state,
            self.providers.herdr.version.as_deref(),
            self.providers.herdr.sessions.as_deref(),
            |session: &HerdrSessionEntry| session.name.as_str(),
            |session: &HerdrSessionEntry| session.tabs.as_deref(),
        )?;
        Ok(())
    }
}

impl WorkspaceSnapshotResponse {
    pub fn new(request_id: String, result: WorkspaceSnapshotResult) -> Self {
        Self {
            v: HOST_PROTOCOL_VERSION,
            message_type: "response".into(),
            request_id,
            result,
        }
    }

    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION || self.message_type != "response" {
            return Err(HostProtocolError::InvalidControlValue);
        }
        validate_request_id(&self.request_id)?;
        self.result.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotRpcResponse {
    Snapshot(WorkspaceSnapshotResponse),
    Error(RpcErrorResponse),
}

pub fn validate_capabilities(capabilities: &[String]) -> Result<(), HostProtocolError> {
    if capabilities.is_empty()
        || capabilities.len() > MAX_CAPABILITY_ENTRIES
        || !capabilities
            .iter()
            .any(|entry| entry == CAPABILITY_TERMINAL_SHELL)
        || !capabilities.iter().all(|entry| {
            !entry.is_empty()
                && entry.len() <= MAX_CAPABILITY_BYTES
                && entry.bytes().all(|byte| byte.is_ascii_graphic())
        })
    {
        return Err(HostProtocolError::InvalidControlValue);
    }
    Ok(())
}

/// Sheds garnish, then rows, until the encoded response fits `MAX_RPC_BODY`.
///
/// A real command surface does not fit. The owner's own Mac reports 136 commands, which encode
/// to **18358 bytes** against a 16384-byte ceiling — so the frame was refused, `write_rpc`'s
/// error was discarded by its caller, and the phone's decode returned an empty catalogue. Every
/// layer reported success and no picker ever appeared. Bounding by `MAX_SLASH_COMMANDS` alone
/// was never enough: 256 commands cannot fit in 16 KB at any per-field bound this uses.
///
/// The order follows Spec 021 §6, which settled the same question for the session list: a row
/// without its garnish beats no row at all. Descriptions go first and from the end, because a
/// name is what gets typed and a description is what makes it readable; hints next; whole
/// commands only when stripping everything still will not fit. The vendor orders this list, and
/// dropping from the end keeps that order rather than inventing a ranking.
pub fn encode_terminal_commands_response_bounded(
    mut response: TerminalCommandsResponse,
) -> Result<(Vec<u8>, TerminalCommandsResponse), HostProtocolError> {
    loop {
        match encode_rpc(&response) {
            Ok(encoded) => return Ok((encoded, response)),
            Err(HostProtocolError::FrameTooLarge) => {}
            Err(error) => return Err(error),
        }
        if let Some(command) = response
            .result
            .commands
            .iter_mut()
            .rev()
            .find(|command| !command.description.is_empty())
        {
            command.description.clear();
            continue;
        }
        if let Some(command) = response
            .result
            .commands
            .iter_mut()
            .rev()
            .find(|command| !command.hint.is_empty())
        {
            command.hint.clear();
            continue;
        }
        // Aliases outlive descriptions and hints: prose makes a row readable, but an alias is
        // often the only spelling the user knows — `/woz-review` rather than `/woz:woz-review`.
        // A row nobody can find is worth less than a row nobody can read.
        if let Some(command) = response
            .result
            .commands
            .iter_mut()
            .rev()
            .find(|command| !command.aliases.is_empty())
        {
            command.aliases.clear();
            continue;
        }
        if response.result.commands.pop().is_some() {
            continue;
        }
        // An empty list that still will not encode is a broken envelope, not a big list.
        return Err(HostProtocolError::FrameTooLarge);
    }
}

/// Cuts a quarter off whichever tab listing is longest, herdr before tmux, and reports whether
/// anything was cut. Order within a listing is the provider's, so the cut comes off the end.
fn shorten_longest_tab_list(response: &mut WorkspaceSnapshotResponse) -> bool {
    let providers = &mut response.result.providers;
    let herdr = providers.herdr.sessions.iter_mut().flatten();
    let longest = herdr
        .filter_map(|entry| entry.tabs.as_mut())
        .chain(
            providers
                .tmux
                .sessions
                .iter_mut()
                .flatten()
                .filter_map(|entry| entry.tabs.as_mut()),
        )
        .filter(|tabs| tabs.len() > 1)
        .max_by_key(|tabs| tabs.len());
    let Some(tabs) = longest else { return false };
    // Strictly decreasing for every length this can see: 2 → 1, 3 → 2, 128 → 96.
    tabs.truncate((tabs.len() * 3 / 4).max(1));
    true
}

/// Drops sessions deterministically until the encoded response fits `MAX_RPC_BODY`: herdr
/// sessions from the end of the list first, then the oldest tmux sessions by `created_unix`.
/// Every dropped session increments `omitted_sessions`.
pub fn encode_snapshot_response_bounded(
    mut response: WorkspaceSnapshotResponse,
) -> Result<(Vec<u8>, WorkspaceSnapshotResponse), HostProtocolError> {
    loop {
        match encode_rpc(&response) {
            Ok(encoded) => return Ok((encoded, response)),
            Err(HostProtocolError::FrameTooLarge) => {}
            Err(error) => return Err(error),
        }
        // Spec 021 §6: tabs are sacrificed first, one session at a time, in exactly the order
        // sessions would be dropped — a session row without its garnish beats no row at all.
        // Stripped tabs never touch `omitted_sessions`: degradation is not omission.
        //
        // Shortening the longest listing goes before nulling whole ones (2026-08-25). An
        // element cap cannot bound an encoded frame — 128 tabs is ~11KB of real labels and 27KB
        // of maxed ones — so this loop is where a long list is really cut, and cutting it to
        // *nothing* would hand the one user who needs the workspace level the empty list it was
        // built to fix. A quarter at a time rather than one tab at a time: shedding singly is
        // the same end state reached in thousands of re-encodes, and a listing this long is
        // being scanned, not counted.
        if shorten_longest_tab_list(&mut response) {
            continue;
        }
        if let Some(sessions) = response.result.providers.herdr.sessions.as_mut()
            && let Some(session) = sessions.iter_mut().rev().find(|entry| entry.tabs.is_some())
        {
            session.tabs = None;
            continue;
        }
        if let Some(sessions) = response.result.providers.tmux.sessions.as_mut() {
            let strip = sessions
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.tabs.is_some())
                .min_by_key(|(index, entry)| (entry.created_unix, *index))
                .map(|(index, _)| index);
            if let Some(index) = strip {
                sessions[index].tabs = None;
                continue;
            }
        }
        let herdr = response.result.providers.herdr.sessions.as_mut();
        if let Some(sessions) = herdr
            && sessions.pop().is_some()
        {
            response.result.omitted_sessions = response.result.omitted_sessions.saturating_add(1);
            continue;
        }
        let tmux = response.result.providers.tmux.sessions.as_mut();
        if let Some(sessions) = tmux
            && !sessions.is_empty()
        {
            let oldest = sessions
                .iter()
                .enumerate()
                .min_by_key(|(index, session)| (session.created_unix, *index))
                .map(|(index, _)| index)
                .expect("non-empty session list has a minimum");
            sessions.remove(oldest);
            response.result.omitted_sessions = response.result.omitted_sessions.saturating_add(1);
            continue;
        }
        return Err(HostProtocolError::FrameTooLarge);
    }
}

pub fn validate_request_id(value: &str) -> Result<(), HostProtocolError> {
    if value.contains('=') {
        return Err(HostProtocolError::InvalidRequestId);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| HostProtocolError::InvalidRequestId)?;
    if decoded.len() != 16 {
        return Err(HostProtocolError::InvalidRequestId);
    }
    Ok(())
}

pub fn validate_endpoint_id_text(value: &str) -> Result<(), HostProtocolError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(HostProtocolError::InvalidControlValue)
    }
}

/// Normalizes a locally derived presentation name by trimming Unicode whitespace, then applies
/// the exact wire bounds. The normalized value is never used as a path, identifier, or argv.
pub fn normalize_host_display_name(value: &str) -> Option<String> {
    let normalized = value.trim();
    valid_host_display_name(normalized).then(|| normalized.to_owned())
}

pub fn valid_host_display_name(value: &str) -> bool {
    let byte_count = value.len();
    if byte_count == 0 || byte_count > MAX_HOST_DISPLAY_NAME_BYTES || value.trim() != value {
        return false;
    }
    value.chars().all(|character| {
        let scalar = character as u32;
        !matches!(scalar, 0x0000..=0x001f | 0x007f..=0x009f | 0x2028 | 0x2029)
            && !matches!(scalar, 0x202a..=0x202e | 0x2066..=0x2069)
    })
}

pub fn valid_host_metadata_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HOST_METADATA_TOKEN_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// Machine tokens are exactly 32 lowercase hex characters: the truncated hash the host
/// derives from its stable machine identifier (the hashing, in host_info, is what keeps
/// the raw id off the wire; this grammar just pins the format byte-exactly).
pub fn valid_machine_token(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub fn decode_rpc_request(body: &[u8]) -> Result<RpcRequest, HostProtocolError> {
    validate_body_size(body, MAX_RPC_BODY)?;
    let value: Value =
        serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
    let method = value
        .as_object()
        .and_then(|object| object.get("method"))
        .and_then(Value::as_str)
        .ok_or(HostProtocolError::MalformedJson)?;
    match method {
        "host.hello" => {
            let request: HostHelloRequest =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            request.validate()?;
            Ok(RpcRequest::Hello(request))
        }
        "host.info" => {
            let request: HostInfoRequest =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            request.validate()?;
            Ok(RpcRequest::HostInfo(request))
        }
        "workspace.snapshot" => {
            let request: WorkspaceSnapshotRequest =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            request.validate()?;
            Ok(RpcRequest::WorkspaceSnapshot(request))
        }
        CAPABILITY_NOTIFICATIONS_REGISTER => {
            let request: NotificationsRegisterRequest =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            request.validate()?;
            Ok(RpcRequest::NotificationsRegister(request))
        }
        CAPABILITY_LIVE_ACTIVITY_REGISTER => {
            let request: LiveActivityRegisterRequest =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            request.validate()?;
            Ok(RpcRequest::LiveActivityRegister(request))
        }
        CAPABILITY_TERMINAL_COMMANDS => {
            let request: TerminalCommandsRequest =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            request.validate()?;
            Ok(RpcRequest::TerminalCommands(request))
        }
        _ => Err(HostProtocolError::UnsupportedMethod),
    }
}

pub fn decode_notifications_response(
    body: &[u8],
) -> Result<NotificationsRpcResponse, HostProtocolError> {
    validate_body_size(body, MAX_RPC_BODY)?;
    let value: Value =
        serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
    let message_type = value
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        .ok_or(HostProtocolError::MalformedJson)?;
    match message_type {
        "response" => {
            let response: NotificationsRegisterResponse =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            response.validate()?;
            Ok(NotificationsRpcResponse::Registered(response))
        }
        "error" => {
            let response: RpcErrorResponse =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            response.validate()?;
            Ok(NotificationsRpcResponse::Error(response))
        }
        _ => Err(HostProtocolError::UnexpectedOrder),
    }
}

pub fn decode_live_activity_response(
    body: &[u8],
) -> Result<LiveActivityRpcResponse, HostProtocolError> {
    validate_body_size(body, MAX_RPC_BODY)?;
    let value: Value =
        serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
    let message_type = value
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        .ok_or(HostProtocolError::MalformedJson)?;
    match message_type {
        "response" => {
            let response: LiveActivityRegisterResponse =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            response.validate()?;
            Ok(LiveActivityRpcResponse::Registered(response))
        }
        "error" => {
            let response: RpcErrorResponse =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            response.validate()?;
            Ok(LiveActivityRpcResponse::Error(response))
        }
        _ => Err(HostProtocolError::UnexpectedOrder),
    }
}

pub fn decode_host_info_response(body: &[u8]) -> Result<HostInfoRpcResponse, HostProtocolError> {
    validate_body_size(body, MAX_RPC_BODY)?;
    let value: Value =
        serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
    let message_type = value
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        .ok_or(HostProtocolError::MalformedJson)?;
    match message_type {
        "response" => {
            let response: HostInfoResponse =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            response.validate()?;
            Ok(HostInfoRpcResponse::Info(response))
        }
        "error" => {
            let response: RpcErrorResponse =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            response.validate()?;
            Ok(HostInfoRpcResponse::Error(response))
        }
        _ => Err(HostProtocolError::UnexpectedOrder),
    }
}

pub fn decode_snapshot_response(body: &[u8]) -> Result<SnapshotRpcResponse, HostProtocolError> {
    validate_body_size(body, MAX_RPC_BODY)?;
    let value: Value =
        serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
    let message_type = value
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        .ok_or(HostProtocolError::MalformedJson)?;
    match message_type {
        "response" => {
            let response: WorkspaceSnapshotResponse =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            response.validate()?;
            Ok(SnapshotRpcResponse::Snapshot(response))
        }
        "error" => {
            let response: RpcErrorResponse =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            response.validate()?;
            Ok(SnapshotRpcResponse::Error(response))
        }
        _ => Err(HostProtocolError::UnexpectedOrder),
    }
}

pub fn decode_rpc_response(body: &[u8]) -> Result<RpcResponse, HostProtocolError> {
    validate_body_size(body, MAX_RPC_BODY)?;
    let value: Value =
        serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
    let message_type = value
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        .ok_or(HostProtocolError::MalformedJson)?;
    match message_type {
        "response" => {
            let response: HostHelloResponse =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            response.validate()?;
            Ok(RpcResponse::Hello(response))
        }
        "error" => {
            let response: RpcErrorResponse =
                serde_json::from_slice(body).map_err(|_| HostProtocolError::MalformedJson)?;
            response.validate()?;
            Ok(RpcResponse::Error(response))
        }
        _ => Err(HostProtocolError::UnexpectedOrder),
    }
}

pub fn encode_rpc<T: Serialize>(value: &T) -> Result<Vec<u8>, HostProtocolError> {
    let body = serde_json::to_vec(value).map_err(|_| HostProtocolError::MalformedJson)?;
    validate_body_size(&body, MAX_RPC_BODY)?;
    let mut encoded = Vec::with_capacity(4 + body.len());
    encoded.extend_from_slice(&(body.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

pub async fn read_rpc_body<R>(reader: &mut R) -> Result<Vec<u8>, HostProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    read_exact(reader, &mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(HostProtocolError::ZeroLength);
    }
    if length > MAX_RPC_BODY {
        return Err(HostProtocolError::FrameTooLarge);
    }
    let mut body = vec![0_u8; length];
    read_exact(reader, &mut body).await?;
    Ok(body)
}

pub async fn write_rpc<W, T>(writer: &mut W, value: &T) -> Result<(), HostProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    writer.write_all(&encode_rpc(value)?).await?;
    Ok(())
}

#[derive(Debug, Default)]
pub struct RpcFrameDecoder {
    buffer: Vec<u8>,
}

impl RpcFrameDecoder {
    pub fn push(&mut self, incoming: &[u8]) -> Result<Vec<Vec<u8>>, HostProtocolError> {
        const MAX_BUFFERED: usize = (MAX_RPC_BODY + 4) * MAX_INCOMING_BIDI_STREAMS as usize;
        if incoming.len() > MAX_BUFFERED.saturating_sub(self.buffer.len()) {
            return Err(HostProtocolError::FrameTooLarge);
        }
        self.buffer.extend_from_slice(incoming);
        let mut bodies = Vec::new();
        loop {
            if self.buffer.len() < 4 {
                break;
            }
            let length =
                u32::from_be_bytes(self.buffer[..4].try_into().expect("four-byte RPC header"))
                    as usize;
            if length == 0 {
                return Err(HostProtocolError::ZeroLength);
            }
            if length > MAX_RPC_BODY {
                return Err(HostProtocolError::FrameTooLarge);
            }
            if self.buffer.len() < 4 + length {
                break;
            }
            bodies.push(self.buffer[4..4 + length].to_vec());
            self.buffer.drain(..4 + length);
        }
        Ok(bodies)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dimensions {
    pub cols: u16,
    pub rows: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl Dimensions {
    pub const MIN_COLS: u16 = 2;
    pub const MAX_COLS: u16 = 500;
    pub const MIN_ROWS: u16 = 1;
    pub const MAX_ROWS: u16 = 300;
    pub const MAX_PIXEL: u16 = 16_384;

    pub fn validate(self) -> Result<Self, HostProtocolError> {
        if !(Self::MIN_COLS..=Self::MAX_COLS).contains(&self.cols)
            || !(Self::MIN_ROWS..=Self::MAX_ROWS).contains(&self.rows)
            || self.pixel_width > Self::MAX_PIXEL
            || self.pixel_height > Self::MAX_PIXEL
        {
            return Err(HostProtocolError::InvalidDimensions);
        }
        Ok(self)
    }

    pub fn encode_resize(self) -> Result<[u8; 8], HostProtocolError> {
        self.validate()?;
        let mut bytes = [0_u8; 8];
        bytes[0..2].copy_from_slice(&self.cols.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.rows.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.pixel_width.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.pixel_height.to_be_bytes());
        Ok(bytes)
    }

    pub fn decode_resize(bytes: &[u8]) -> Result<Self, HostProtocolError> {
        if bytes.len() != 8 {
            return Err(HostProtocolError::InvalidDimensions);
        }
        Self {
            cols: u16::from_be_bytes([bytes[0], bytes[1]]),
            rows: u16::from_be_bytes([bytes[2], bytes[3]]),
            pixel_width: u16::from_be_bytes([bytes[4], bytes[5]]),
            pixel_height: u16::from_be_bytes([bytes[6], bytes[7]]),
        }
        .validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalOpen {
    pub v: u8,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Spec 021 §3.4: a one-shot focus hint, never part of the target's identity. Only attach
    /// targets may carry it, and the app only sends it for rows a tabs-capable host produced,
    /// so a host that predates the field (and would refuse the unknown key) never sees it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tab: Option<String>,
    #[serde(flatten)]
    pub dimensions: Dimensions,
}

impl TerminalOpen {
    pub fn validate(&self) -> Result<(), HostProtocolError> {
        self.validated_target()?;
        Ok(())
    }

    /// Every open is fully validated before any process spawn: the target must be one of the
    /// fixed enum values, and a bounded session/route ID must be present exactly when required
    /// requires one and must satisfy the §5.4 session-name rule.
    pub fn validated_target(&self) -> Result<TerminalTarget, HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION {
            return Err(HostProtocolError::UnsupportedVersion);
        }
        let target =
            TerminalTarget::from_wire(&self.target).ok_or(HostProtocolError::UnsupportedTarget)?;
        match (&self.session, target.requires_session()) {
            (None, false) => {}
            (Some(session), true) if valid_session_name(session) => {}
            _ => return Err(HostProtocolError::InvalidTarget),
        }
        if let Some(tab) = &self.tab {
            // A tab hint is meaningful only where there is an existing multiplexer session to
            // focus inside; every other target refuses it rather than ignoring it.
            let attach = matches!(
                target,
                TerminalTarget::TmuxAttach | TerminalTarget::HerdrAttach
            );
            if !attach || !valid_tab_id(tab) {
                return Err(HostProtocolError::InvalidTarget);
            }
        }
        self.dimensions.validate()?;
        Ok(target)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalOpened {
    pub v: u8,
    pub terminal_id: String,
    #[serde(flatten)]
    pub dimensions: Dimensions,
    pub term: String,
}

impl TerminalOpened {
    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION || self.term != "xterm-256color" {
            return Err(HostProtocolError::InvalidControlValue);
        }
        validate_terminal_id(&self.terminal_id)?;
        self.dimensions.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalExit {
    pub v: u8,
    pub terminal_id: String,
    pub kind: String,
    pub code: Option<u32>,
    pub signal: Option<String>,
}

impl TerminalExit {
    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION {
            return Err(HostProtocolError::UnsupportedVersion);
        }
        validate_terminal_id(&self.terminal_id)?;
        match self.kind.as_str() {
            "closed" | "server_shutdown" if self.code.is_none() && self.signal.is_none() => Ok(()),
            "exited" if self.code.is_some() && self.signal.is_none() => Ok(()),
            "signaled" if self.code.is_none() => {
                let signal = self
                    .signal
                    .as_deref()
                    .ok_or(HostProtocolError::InvalidControlValue)?;
                if !signal.is_empty()
                    && signal.len() <= 32
                    && signal.bytes().all(|byte| byte.is_ascii())
                {
                    Ok(())
                } else {
                    Err(HostProtocolError::InvalidControlValue)
                }
            }
            _ => Err(HostProtocolError::InvalidControlValue),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalError {
    pub v: u8,
    pub terminal_id: Option<String>,
    pub code: String,
    pub message: String,
}

impl TerminalError {
    pub fn validate(&self) -> Result<(), HostProtocolError> {
        if self.v != HOST_PROTOCOL_VERSION {
            return Err(HostProtocolError::UnsupportedVersion);
        }
        if let Some(terminal_id) = &self.terminal_id {
            validate_terminal_id(terminal_id)?;
        }
        validate_code_and_message(&self.code, &self.message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalFrame {
    Open(TerminalOpen),
    Opened(TerminalOpened),
    Input(Vec<u8>),
    Output(Vec<u8>),
    Resize(Dimensions),
    Close,
    Exit(TerminalExit),
    Error(TerminalError),
}

impl TerminalFrame {
    pub const fn frame_type(&self) -> u8 {
        match self {
            Self::Open(_) => 0x01,
            Self::Opened(_) => 0x02,
            Self::Input(_) => 0x03,
            Self::Output(_) => 0x04,
            Self::Resize(_) => 0x05,
            Self::Close => 0x06,
            Self::Exit(_) => 0x07,
            Self::Error(_) => 0x08,
        }
    }
}

pub fn terminal_frame_payload_limit(frame_type: u8) -> Result<usize, HostProtocolError> {
    match frame_type {
        0x01 => Ok(MAX_OPEN_PAYLOAD),
        0x02 => Ok(MAX_OPENED_PAYLOAD),
        0x03 | 0x04 => Ok(MAX_DATA_PAYLOAD),
        0x05 => Ok(8),
        0x06 => Ok(0),
        0x07 => Ok(MAX_EXIT_PAYLOAD),
        0x08 => Ok(MAX_ERROR_PAYLOAD),
        _ => Err(HostProtocolError::UnknownFrameType),
    }
}

pub fn encode_terminal_frame(frame: &TerminalFrame) -> Result<Vec<u8>, HostProtocolError> {
    let payload = match frame {
        TerminalFrame::Open(value) => {
            value.validate()?;
            serde_json::to_vec(value).map_err(|_| HostProtocolError::MalformedJson)?
        }
        TerminalFrame::Opened(value) => {
            value.validate()?;
            serde_json::to_vec(value).map_err(|_| HostProtocolError::MalformedJson)?
        }
        TerminalFrame::Input(value) | TerminalFrame::Output(value) => value.clone(),
        TerminalFrame::Resize(value) => value.encode_resize()?.to_vec(),
        TerminalFrame::Close => Vec::new(),
        TerminalFrame::Exit(value) => {
            value.validate()?;
            serde_json::to_vec(value).map_err(|_| HostProtocolError::MalformedJson)?
        }
        TerminalFrame::Error(value) => {
            value.validate()?;
            serde_json::to_vec(value).map_err(|_| HostProtocolError::MalformedJson)?
        }
    };
    validate_terminal_payload(frame.frame_type(), &payload)?;
    let mut encoded = Vec::with_capacity(5 + payload.len());
    encoded.push(frame.frame_type());
    encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

pub fn decode_terminal_frame(
    frame_type: u8,
    payload: &[u8],
) -> Result<TerminalFrame, HostProtocolError> {
    validate_terminal_payload(frame_type, payload)?;
    match frame_type {
        0x01 => {
            let value: TerminalOpen = strict_json(payload)?;
            value.validate()?;
            Ok(TerminalFrame::Open(value))
        }
        0x02 => {
            let value: TerminalOpened = strict_json(payload)?;
            value.validate()?;
            Ok(TerminalFrame::Opened(value))
        }
        0x03 => Ok(TerminalFrame::Input(payload.to_vec())),
        0x04 => Ok(TerminalFrame::Output(payload.to_vec())),
        0x05 => Ok(TerminalFrame::Resize(Dimensions::decode_resize(payload)?)),
        0x06 => Ok(TerminalFrame::Close),
        0x07 => {
            let value: TerminalExit = strict_json(payload)?;
            value.validate()?;
            Ok(TerminalFrame::Exit(value))
        }
        0x08 => {
            let value: TerminalError = strict_json(payload)?;
            value.validate()?;
            Ok(TerminalFrame::Error(value))
        }
        _ => Err(HostProtocolError::UnknownFrameType),
    }
}

pub async fn read_terminal_frame<R>(reader: &mut R) -> Result<TerminalFrame, HostProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 5];
    read_exact(reader, &mut header).await?;
    let frame_type = header[0];
    let length =
        u32::from_be_bytes(header[1..5].try_into().expect("four-byte frame length")) as usize;
    let limit = terminal_frame_payload_limit(frame_type)?;
    if length > limit {
        return Err(HostProtocolError::FrameTooLarge);
    }
    validate_terminal_payload_length(frame_type, length)?;
    let mut payload = vec![0_u8; length];
    read_exact(reader, &mut payload).await?;
    decode_terminal_frame(frame_type, &payload)
}

pub async fn write_terminal_frame<W>(
    writer: &mut W,
    frame: &TerminalFrame,
) -> Result<(), HostProtocolError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&encode_terminal_frame(frame)?).await?;
    Ok(())
}

#[derive(Debug, Default)]
pub struct TerminalFrameDecoder {
    buffer: Vec<u8>,
}

impl TerminalFrameDecoder {
    pub fn push(&mut self, incoming: &[u8]) -> Result<Vec<TerminalFrame>, HostProtocolError> {
        const MAX_BUFFERED: usize = (MAX_DATA_PAYLOAD + 5) * MAX_INCOMING_BIDI_STREAMS as usize;
        if incoming.len() > MAX_BUFFERED.saturating_sub(self.buffer.len()) {
            return Err(HostProtocolError::FrameTooLarge);
        }
        self.buffer.extend_from_slice(incoming);
        let mut frames = Vec::new();
        loop {
            if self.buffer.len() < 5 {
                break;
            }
            let frame_type = self.buffer[0];
            let length = u32::from_be_bytes(
                self.buffer[1..5]
                    .try_into()
                    .expect("four-byte terminal frame length"),
            ) as usize;
            let limit = terminal_frame_payload_limit(frame_type)?;
            if length > limit {
                return Err(HostProtocolError::FrameTooLarge);
            }
            validate_terminal_payload_length(frame_type, length)?;
            if self.buffer.len() < 5 + length {
                break;
            }
            frames.push(decode_terminal_frame(
                frame_type,
                &self.buffer[5..5 + length],
            )?);
            self.buffer.drain(..5 + length);
        }
        Ok(frames)
    }
}

/// Frame reader that is safe to drop mid-read, unlike `read_terminal_frame`, whose `read_exact`
/// loses already-consumed bytes when a `tokio::select!` picks another branch. The terminal bridge
/// drops its read future on every PTY output event, so under fragmented delivery (an LTE relay
/// path) a partial header vanished and the stream desynced into "The terminal frame was
/// malformed". Bytes here are consumed only by single completed `read` calls — cancellation-safe
/// by tokio's contract — and buffered in the decoder, which outlives the future.
#[derive(Debug)]
pub struct TerminalFrameReader {
    decoder: TerminalFrameDecoder,
    queue: VecDeque<TerminalFrame>,
    buffer: Vec<u8>,
}

impl Default for TerminalFrameReader {
    fn default() -> Self {
        Self {
            decoder: TerminalFrameDecoder::default(),
            queue: VecDeque::new(),
            buffer: vec![0_u8; 8 * 1024],
        }
    }
}

impl TerminalFrameReader {
    /// Cancellation-safe: dropping the returned future never loses stream position.
    pub async fn next<R>(&mut self, reader: &mut R) -> Result<TerminalFrame, HostProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            if let Some(frame) = self.queue.pop_front() {
                return Ok(frame);
            }
            let count = match reader.read(&mut self.buffer).await {
                Ok(0) => return Err(HostProtocolError::Truncated),
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(HostProtocolError::Truncated);
                }
                Err(error) => return Err(HostProtocolError::Io(error)),
            };
            self.queue.extend(self.decoder.push(&self.buffer[..count])?);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDirection {
    ClientToHost,
    HostToClient,
}

pub fn validate_frame_direction(
    frame: &TerminalFrame,
    direction: FrameDirection,
) -> Result<(), HostProtocolError> {
    let valid = matches!(
        (direction, frame),
        (
            FrameDirection::ClientToHost,
            TerminalFrame::Open(_)
                | TerminalFrame::Input(_)
                | TerminalFrame::Resize(_)
                | TerminalFrame::Close
        ) | (
            FrameDirection::HostToClient,
            TerminalFrame::Opened(_)
                | TerminalFrame::Output(_)
                | TerminalFrame::Exit(_)
                | TerminalFrame::Error(_)
        )
    );
    valid
        .then_some(())
        .ok_or(HostProtocolError::UnexpectedDirection)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostReceiveState {
    AwaitingOpen,
    Attached,
    Finished,
}

impl HostReceiveState {
    pub fn accept(self, frame: &TerminalFrame) -> Result<Self, HostProtocolError> {
        validate_frame_direction(frame, FrameDirection::ClientToHost)?;
        match (self, frame) {
            (Self::AwaitingOpen, TerminalFrame::Open(_)) => Ok(Self::Attached),
            (Self::Attached, TerminalFrame::Input(_) | TerminalFrame::Resize(_)) => {
                Ok(Self::Attached)
            }
            (Self::Attached, TerminalFrame::Close) => Ok(Self::Finished),
            _ => Err(HostProtocolError::UnexpectedOrder),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientReceiveState {
    AwaitingOpened,
    Attached,
    Finished,
}

impl ClientReceiveState {
    pub fn accept(self, frame: &TerminalFrame) -> Result<Self, HostProtocolError> {
        validate_frame_direction(frame, FrameDirection::HostToClient)?;
        match (self, frame) {
            (Self::AwaitingOpened, TerminalFrame::Opened(_)) => Ok(Self::Attached),
            (Self::AwaitingOpened, TerminalFrame::Error(_)) => Ok(Self::Finished),
            (Self::Attached, TerminalFrame::Output(_)) => Ok(Self::Attached),
            (Self::Attached, TerminalFrame::Exit(_) | TerminalFrame::Error(_)) => {
                Ok(Self::Finished)
            }
            _ => Err(HostProtocolError::UnexpectedOrder),
        }
    }
}

fn validate_terminal_id(value: &str) -> Result<(), HostProtocolError> {
    if value.contains('=') {
        return Err(HostProtocolError::InvalidTerminalId);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| HostProtocolError::InvalidTerminalId)?;
    if decoded.len() == 16 {
        Ok(())
    } else {
        Err(HostProtocolError::InvalidTerminalId)
    }
}

fn validate_code_and_message(code: &str, message: &str) -> Result<(), HostProtocolError> {
    if code.is_empty()
        || code.len() > 64
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        || message.len() > 256
    {
        return Err(HostProtocolError::InvalidControlValue);
    }
    Ok(())
}

fn validate_body_size(body: &[u8], maximum: usize) -> Result<(), HostProtocolError> {
    if body.is_empty() {
        return Err(HostProtocolError::ZeroLength);
    }
    if body.len() > maximum {
        return Err(HostProtocolError::FrameTooLarge);
    }
    Ok(())
}

fn validate_terminal_payload(frame_type: u8, payload: &[u8]) -> Result<(), HostProtocolError> {
    let limit = terminal_frame_payload_limit(frame_type)?;
    if payload.len() > limit {
        return Err(HostProtocolError::FrameTooLarge);
    }
    validate_terminal_payload_length(frame_type, payload.len())
}

fn validate_terminal_payload_length(
    frame_type: u8,
    length: usize,
) -> Result<(), HostProtocolError> {
    match frame_type {
        0x03 | 0x04 if length == 0 => Err(HostProtocolError::ZeroLength),
        0x05 if length != 8 => Err(HostProtocolError::InvalidDimensions),
        0x06 if length != 0 => Err(HostProtocolError::InvalidControlValue),
        0x01 | 0x02 | 0x07 | 0x08 if length == 0 => Err(HostProtocolError::ZeroLength),
        _ => Ok(()),
    }
}

fn strict_json<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> Result<T, HostProtocolError> {
    serde_json::from_slice(payload).map_err(|_| HostProtocolError::MalformedJson)
}

async fn read_exact<R>(reader: &mut R, buffer: &mut [u8]) -> Result<(), HostProtocolError>
where
    R: AsyncRead + Unpin,
{
    match reader.read_exact(buffer).await {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(HostProtocolError::Truncated)
        }
        Err(error) => Err(HostProtocolError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    const REQUEST_ID: &str = "AAECAwQFBgcICQoLDA0ODw";
    const TERMINAL_ID: &str = "EBESExQVFhcYGRobHB0eHw";
    const HOST_ID: &str = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6";
    const INSTALLATION_ID: &str =
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    fn hello_request() -> HostHelloRequest {
        HostHelloRequest {
            v: 1,
            message_type: "request".into(),
            request_id: REQUEST_ID.into(),
            method: "host.hello".into(),
            params: HostHelloParams {
                min_protocol: 1,
                max_protocol: 1,
            },
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

    fn opened() -> TerminalOpened {
        TerminalOpened {
            v: 1,
            terminal_id: TERMINAL_ID.into(),
            dimensions: dimensions(),
            term: "xterm-256color".into(),
        }
    }

    #[test]
    fn stream_preface_version_and_kind_are_strict() {
        assert_eq!(decode_stream_preface([1, 1]).unwrap(), StreamKind::Rpc);
        assert_eq!(decode_stream_preface([1, 2]).unwrap(), StreamKind::Terminal);
        assert_eq!(decode_stream_preface([1, 3]).unwrap(), StreamKind::Agent);
        assert_eq!(decode_stream_preface([1, 5]).unwrap(), StreamKind::Upload);
        assert_eq!(decode_stream_preface([1, 7]).unwrap(), StreamKind::Download);
        assert_eq!(decode_stream_preface([1, 8]).unwrap(), StreamKind::Forward);
        assert!(matches!(
            decode_stream_preface([2, 1]),
            Err(HostProtocolError::UnsupportedVersion)
        ));
        // 0x04 (Spec 008) and 0x06 (Spec 010) are reserved by comment only; until those specs
        // are built, both bytes must keep failing as unknown.
        assert!(matches!(
            decode_stream_preface([1, 4]),
            Err(HostProtocolError::UnknownStreamKind)
        ));
        assert!(matches!(
            decode_stream_preface([1, 6]),
            Err(HostProtocolError::UnknownStreamKind)
        ));
    }

    #[tokio::test]
    async fn stream_preface_timeout_is_bounded() {
        let (_writer, mut reader) = tokio::io::duplex(8);
        assert!(matches!(
            read_stream_preface_with_timeout(&mut reader, Duration::from_millis(10)).await,
            Err(HostProtocolError::PrefaceTimeout)
        ));
    }

    #[test]
    fn rpc_fragmentation_coalescing_and_strict_json() {
        let first = encode_rpc(&hello_request()).unwrap();
        let second = encode_rpc(&hello_request()).unwrap();
        let mut decoder = RpcFrameDecoder::default();
        assert!(decoder.push(&first[..2]).unwrap().is_empty());
        assert!(decoder.push(&first[2..7]).unwrap().is_empty());
        let mut tail = first[7..].to_vec();
        tail.extend_from_slice(&second);
        let bodies = decoder.push(&tail).unwrap();
        assert_eq!(bodies.len(), 2);
        assert_eq!(
            decode_rpc_request(&bodies[0]).unwrap(),
            RpcRequest::Hello(hello_request())
        );

        for malformed in [
            br#"{"v":1,"type":"request","request_id":"AAECAwQFBgcICQoLDA0ODw","method":"host.hello","params":{"min_protocol":1,"max_protocol":1},"extra":true}"#.as_slice(),
            br#"{"v":1,"v":1,"type":"request","request_id":"AAECAwQFBgcICQoLDA0ODw","method":"host.hello","params":{"min_protocol":1,"max_protocol":1}}"#.as_slice(),
            br#"not-json"#.as_slice(),
        ] {
            assert!(matches!(
                decode_rpc_request(malformed),
                Err(HostProtocolError::MalformedJson)
            ));
        }
    }

    #[test]
    fn rpc_lengths_ids_methods_versions_and_correlation_are_bounded() {
        assert!(matches!(
            RpcFrameDecoder::default().push(&0_u32.to_be_bytes()),
            Err(HostProtocolError::ZeroLength)
        ));
        assert!(matches!(
            RpcFrameDecoder::default().push(&((MAX_RPC_BODY + 1) as u32).to_be_bytes()),
            Err(HostProtocolError::FrameTooLarge)
        ));

        let mut request = hello_request();
        request.request_id = "short".into();
        assert!(matches!(
            request.validate(),
            Err(HostProtocolError::InvalidRequestId)
        ));
        request = hello_request();
        request.method = "shell.exec".into();
        assert!(matches!(
            request.validate(),
            Err(HostProtocolError::UnsupportedMethod)
        ));
        request = hello_request();
        request.params.min_protocol = 2;
        assert!(matches!(
            request.validate(),
            Err(HostProtocolError::UnsupportedVersion)
        ));

        let response =
            HostHelloResponse::new(REQUEST_ID.into(), HOST_ID.into(), INSTALLATION_ID.into());
        response.validate().unwrap();
        assert_eq!(response.request_id, hello_request().request_id);
        assert_eq!(response.result.limits, HostLimits::default());
    }

    #[test]
    fn shared_host_hello_fixture_is_golden() {
        #[derive(Deserialize)]
        struct Fixture {
            request: Value,
            response: Value,
            error: Value,
        }
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase1/host-hello-v1.json"
        );
        let fixture: Fixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let request = decode_rpc_request(&serde_json::to_vec(&fixture.request).unwrap()).unwrap();
        assert_eq!(request, RpcRequest::Hello(hello_request()));
        let response =
            decode_rpc_response(&serde_json::to_vec(&fixture.response).unwrap()).unwrap();
        assert!(matches!(response, RpcResponse::Hello(_)));
        let error = decode_rpc_response(&serde_json::to_vec(&fixture.error).unwrap()).unwrap();
        assert!(matches!(error, RpcResponse::Error(_)));
    }

    #[test]
    fn shared_host_info_fixture_and_hostile_fields_are_strict() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase3/host-info-v1.json"
        );
        let fixture: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let request_body = serde_json::to_vec(fixture.get("request").unwrap()).unwrap();
        assert_eq!(
            decode_rpc_request(&request_body).unwrap(),
            RpcRequest::HostInfo(HostInfoRequest::new(REQUEST_ID.into()))
        );
        let response_body = serde_json::to_vec(fixture.get("response").unwrap()).unwrap();
        let HostInfoRpcResponse::Info(response) =
            decode_host_info_response(&response_body).unwrap()
        else {
            panic!("expected host info response");
        };
        assert_eq!(response.result.display_name, "fixture-host");
        assert_eq!(response.result.platform, "linux");
        assert_eq!(response.result.distribution.as_deref(), Some("debian"));
        assert_eq!(response.result.distribution_version.as_deref(), Some("13"));
        assert_eq!(response.result.architecture, "x86_64");
        assert_eq!(
            response.result.machine_token.as_deref(),
            Some("3f2a9c8d1e4b5a6f7c8d9e0f1a2b3c4d")
        );

        for value in fixture
            .get("valid_display_names")
            .unwrap()
            .as_array()
            .unwrap()
        {
            assert!(valid_host_display_name(value.as_str().unwrap()));
        }
        for value in fixture
            .get("invalid_display_names")
            .unwrap()
            .as_array()
            .unwrap()
        {
            assert!(!valid_host_display_name(value.as_str().unwrap()));
        }
        for value in fixture.get("valid_tokens").unwrap().as_array().unwrap() {
            assert!(valid_host_metadata_token(value.as_str().unwrap()));
        }
        for value in fixture.get("invalid_tokens").unwrap().as_array().unwrap() {
            assert!(!valid_host_metadata_token(value.as_str().unwrap()));
        }
        for value in fixture
            .get("valid_machine_tokens")
            .unwrap()
            .as_array()
            .unwrap()
        {
            assert!(valid_machine_token(value.as_str().unwrap()));
        }
        for value in fixture
            .get("invalid_machine_tokens")
            .unwrap()
            .as_array()
            .unwrap()
        {
            assert!(!valid_machine_token(value.as_str().unwrap()));
        }

        let mut unknown = fixture.get("response").unwrap().clone();
        unknown["result"]["authority"] = json!(true);
        assert!(matches!(
            decode_host_info_response(&serde_json::to_vec(&unknown).unwrap()),
            Err(HostProtocolError::MalformedJson)
        ));
        let mac_with_distribution = HostInfoResult {
            v: 1,
            display_name: "fixture-host".into(),
            platform: "macos".into(),
            distribution: Some("macos".into()),
            distribution_version: None,
            architecture: "aarch64".into(),
            machine_token: None,
            version: None,
        };
        assert!(mac_with_distribution.validate().is_err());

        let bad_machine_token = HostInfoResult {
            v: 1,
            display_name: "fixture-host".into(),
            platform: "linux".into(),
            distribution: None,
            distribution_version: None,
            architecture: "x86_64".into(),
            machine_token: Some("Not-Hex".into()),
            version: None,
        };
        assert!(bad_machine_token.validate().is_err());

        // A host predating the version field sends nothing, and that has to decode rather than
        // fail. This is why the field is additive and optional instead of a protocol bump: a bump
        // would make every already-installed host read as unsupported to gain one diagnostic.
        let mut without_version = fixture.get("response").unwrap().clone();
        without_version["result"]
            .as_object_mut()
            .unwrap()
            .remove("version");
        let decoded = decode_host_info_response(&serde_json::to_vec(&without_version).unwrap());
        assert!(matches!(
            decoded,
            Ok(HostInfoRpcResponse::Info(response)) if response.result.version.is_none()
        ));

        let bad_version = HostInfoResult {
            v: 1,
            display_name: "fixture-host".into(),
            platform: "linux".into(),
            distribution: None,
            distribution_version: None,
            architecture: "x86_64".into(),
            machine_token: None,
            version: Some("0.1.8 (dirty)".into()),
        };
        assert!(bad_version.validate().is_err());
    }

    #[test]
    fn terminal_frames_fragment_coalesce_and_preserve_opaque_bytes() {
        let raw = vec![0xff, 0xf0, 0x80, b'a', 0x00];
        let output = TerminalFrame::Output(raw.clone());
        let resize = TerminalFrame::Resize(dimensions());
        let first = encode_terminal_frame(&output).unwrap();
        let second = encode_terminal_frame(&resize).unwrap();
        let mut decoder = TerminalFrameDecoder::default();
        assert!(decoder.push(&first[..3]).unwrap().is_empty());
        let mut tail = first[3..].to_vec();
        tail.extend_from_slice(&second);
        assert_eq!(decoder.push(&tail).unwrap(), vec![output, resize]);
    }

    #[test]
    fn every_terminal_frame_payload_limit_is_enforced_before_payload_use() {
        for (frame_type, limit) in [
            (0x01, MAX_OPEN_PAYLOAD),
            (0x02, MAX_OPENED_PAYLOAD),
            (0x03, MAX_DATA_PAYLOAD),
            (0x04, MAX_DATA_PAYLOAD),
            (0x05, 8),
            (0x06, 0),
            (0x07, MAX_EXIT_PAYLOAD),
            (0x08, MAX_ERROR_PAYLOAD),
        ] {
            let mut header = vec![frame_type];
            header.extend_from_slice(&((limit + 1) as u32).to_be_bytes());
            assert!(matches!(
                TerminalFrameDecoder::default().push(&header),
                Err(HostProtocolError::FrameTooLarge)
            ));
        }
        assert!(matches!(
            decode_terminal_frame(0x03, &[]),
            Err(HostProtocolError::ZeroLength)
        ));
        assert!(matches!(
            decode_terminal_frame(0x06, &[1]),
            Err(HostProtocolError::FrameTooLarge | HostProtocolError::InvalidControlValue)
        ));
    }

    #[test]
    fn resize_is_big_endian_and_hard_bounded() {
        let value = Dimensions {
            cols: 500,
            rows: 300,
            pixel_width: 16_384,
            pixel_height: 0,
        };
        assert_eq!(
            value.encode_resize().unwrap(),
            [0x01, 0xf4, 0x01, 0x2c, 0x40, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            Dimensions::decode_resize(&value.encode_resize().unwrap()).unwrap(),
            value
        );
        assert!(
            Dimensions {
                cols: 1,
                ..dimensions()
            }
            .validate()
            .is_err()
        );
        assert!(
            Dimensions {
                rows: 301,
                ..dimensions()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn frame_direction_and_state_order_fail_closed() {
        let open = TerminalFrame::Open(TerminalOpen {
            v: 1,
            target: "shell".into(),
            session: None,
            tab: None,
            dimensions: dimensions(),
        });
        let opened = TerminalFrame::Opened(opened());
        let input = TerminalFrame::Input(vec![1]);
        let output = TerminalFrame::Output(vec![2]);
        let close = TerminalFrame::Close;
        let exit = TerminalFrame::Exit(TerminalExit {
            v: 1,
            terminal_id: TERMINAL_ID.into(),
            kind: "closed".into(),
            code: None,
            signal: None,
        });

        assert!(HostReceiveState::AwaitingOpen.accept(&input).is_err());
        let host = HostReceiveState::AwaitingOpen.accept(&open).unwrap();
        assert_eq!(host.accept(&input).unwrap(), HostReceiveState::Attached);
        assert_eq!(host.accept(&close).unwrap(), HostReceiveState::Finished);
        assert!(host.accept(&output).is_err());

        assert!(ClientReceiveState::AwaitingOpened.accept(&output).is_err());
        let client = ClientReceiveState::AwaitingOpened.accept(&opened).unwrap();
        assert_eq!(
            client.accept(&output).unwrap(),
            ClientReceiveState::Attached
        );
        assert_eq!(client.accept(&exit).unwrap(), ClientReceiveState::Finished);
        assert!(client.accept(&input).is_err());
    }

    #[test]
    fn shared_terminal_and_reset_fixtures_are_golden() {
        #[derive(Deserialize)]
        struct Fixture {
            stream_prefaces_hex: std::collections::BTreeMap<String, String>,
            resize_payload_hex: String,
            frames: Vec<FixtureFrame>,
            reset_codes: std::collections::BTreeMap<String, u32>,
        }
        #[derive(Deserialize)]
        struct FixtureFrame {
            frame_type: u8,
            payload_base64url: String,
        }
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase1/terminal-frames-v1.json"
        );
        let fixture: Fixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(fixture.stream_prefaces_hex["rpc"], "0101");
        assert_eq!(fixture.stream_prefaces_hex["terminal"], "0102");
        assert_eq!(fixture.resize_payload_hex, "0050001800000000");
        for frame in fixture.frames {
            let payload = URL_SAFE_NO_PAD.decode(frame.payload_base64url).unwrap();
            decode_terminal_frame(frame.frame_type, &payload).unwrap();
        }
        assert_eq!(
            fixture.reset_codes["connection_authorization_denied"],
            CONNECTION_AUTHORIZATION_DENIED
        );
        assert_eq!(
            fixture.reset_codes["connection_protocol_violation"],
            CONNECTION_PROTOCOL_VIOLATION
        );
        assert_eq!(fixture.reset_codes["connection_busy"], CONNECTION_BUSY);
        assert_eq!(
            fixture.reset_codes["connection_server_shutdown"],
            CONNECTION_SERVER_SHUTDOWN
        );
        assert_eq!(fixture.reset_codes["stream_cancelled"], STREAM_CANCELLED);
        assert_eq!(fixture.reset_codes["stream_malformed"], STREAM_MALFORMED);
        assert_eq!(
            fixture.reset_codes["stream_frame_too_large"],
            STREAM_FRAME_TOO_LARGE
        );
        assert_eq!(fixture.reset_codes["stream_unexpected"], STREAM_UNEXPECTED);
        assert_eq!(
            fixture.reset_codes["stream_terminal_limit"],
            STREAM_TERMINAL_LIMIT
        );
        assert_eq!(
            fixture.reset_codes["stream_pty_failure"],
            STREAM_PTY_FAILURE
        );
        assert_eq!(
            fixture.reset_codes["stream_backpressure"],
            STREAM_BACKPRESSURE
        );
        assert_eq!(fixture.reset_codes["stream_internal"], STREAM_INTERNAL);
    }

    #[test]
    fn shared_malformed_fixture_cases_fail_as_declared() {
        #[derive(Deserialize)]
        struct Fixture {
            rpc_bodies: Vec<MalformedBody>,
            terminal_headers_hex: Vec<MalformedHeader>,
        }
        #[derive(Deserialize)]
        struct MalformedBody {
            json: String,
            error: String,
        }
        #[derive(Deserialize)]
        struct MalformedHeader {
            hex: String,
            error: String,
        }
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase1/malformed-v1.json"
        );
        let fixture: Fixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        for body in fixture.rpc_bodies {
            let error = decode_rpc_request(body.json.as_bytes()).unwrap_err();
            let actual = match error {
                HostProtocolError::UnsupportedVersion => "unsupported_version",
                HostProtocolError::UnsupportedMethod => "unsupported_method",
                HostProtocolError::InvalidRequestId => "invalid_request_id",
                HostProtocolError::MalformedJson => "malformed_request",
                other => panic!("unexpected malformed fixture result: {other}"),
            };
            assert_eq!(actual, body.error);
        }
        for header in fixture.terminal_headers_hex {
            let bytes = hex_decode(&header.hex);
            let error = TerminalFrameDecoder::default().push(&bytes).unwrap_err();
            let actual = match error {
                HostProtocolError::FrameTooLarge => "frame_too_large",
                HostProtocolError::UnknownFrameType => "unknown_frame_type",
                HostProtocolError::ZeroLength => "zero_length",
                HostProtocolError::InvalidDimensions => "invalid_dimensions",
                other => panic!("unexpected malformed header result: {other}"),
            };
            assert_eq!(actual, header.error);
        }
    }

    #[tokio::test]
    async fn async_readers_accept_partial_reads_without_frame_assumptions() {
        let encoded =
            encode_terminal_frame(&TerminalFrame::Output(vec![0xf0, 0x9f, 0x91, 0x8b])).unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(8);
        let task = tokio::spawn(async move {
            for byte in encoded {
                writer.write_all(&[byte]).await.unwrap();
            }
        });
        assert_eq!(
            read_terminal_frame(&mut reader).await.unwrap(),
            TerminalFrame::Output(vec![0xf0, 0x9f, 0x91, 0x8b])
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn frame_reader_survives_select_style_cancellation_mid_frame() {
        // bridge_terminal drops its read future whenever another select! branch wins — every
        // PTY output event. Deliver frames one byte at a time and drop a freshly polled read
        // future after every byte: the worst-case schedule a fragmented LTE relay path
        // produces. Every frame must still come out intact and in order.
        let frames = vec![
            TerminalFrame::Input(b"hello".to_vec()),
            TerminalFrame::Resize(dimensions()),
            TerminalFrame::Input(b"world".to_vec()),
            TerminalFrame::Close,
        ];
        let bytes: Vec<u8> = frames
            .iter()
            .flat_map(|frame| encode_terminal_frame(frame).unwrap())
            .collect();
        let (mut writer, mut stream) = tokio::io::duplex(8);
        let mut frame_reader = TerminalFrameReader::default();
        let mut received = Vec::new();
        for byte in bytes {
            writer.write_all(&[byte]).await.unwrap();
            let mut read = std::pin::pin!(frame_reader.next(&mut stream));
            let polled =
                std::future::poll_fn(|context| std::task::Poll::Ready(read.as_mut().poll(context)))
                    .await;
            if let std::task::Poll::Ready(result) = polled {
                received.push(result.unwrap());
            }
            // `read` drops here mid-frame, exactly as the select! does. Swapping this reader
            // back to `read_terminal_frame` makes the drain below time out — bytes lost.
        }
        while received.len() < frames.len() {
            let frame = timeout(Duration::from_millis(500), frame_reader.next(&mut stream))
                .await
                .expect("stream desynced: bytes were lost to a cancelled read")
                .unwrap();
            received.push(frame);
        }
        assert_eq!(received, frames);
    }

    #[test]
    fn strict_terminal_control_json_rejects_unknown_duplicate_and_invalid_values() {
        let unknown = json!({
            "v": 1,
            "target": "shell",
            "cols": 80,
            "rows": 24,
            "pixel_width": 0,
            "pixel_height": 0,
            "command": "not allowed"
        });
        assert!(matches!(
            decode_terminal_frame(0x01, &serde_json::to_vec(&unknown).unwrap()),
            Err(HostProtocolError::MalformedJson)
        ));
        let duplicate = br#"{"v":1,"target":"shell","cols":80,"cols":81,"rows":24,"pixel_width":0,"pixel_height":0}"#;
        assert!(matches!(
            decode_terminal_frame(0x01, duplicate),
            Err(HostProtocolError::MalformedJson)
        ));
        let unsupported = TerminalOpen {
            v: 1,
            target: "exec".into(),
            session: None,
            tab: None,
            dimensions: dimensions(),
        };
        assert!(matches!(
            encode_terminal_frame(&TerminalFrame::Open(unsupported)),
            Err(HostProtocolError::UnsupportedTarget)
        ));
    }

    fn hex_decode(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    fn phase2_fixture(name: &str) -> Value {
        let path = format!(
            "{}/../../protocol/fixtures/phase2/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn classify(error: &HostProtocolError) -> &'static str {
        match error {
            HostProtocolError::UnsupportedVersion => "unsupported_version",
            HostProtocolError::UnsupportedMethod => "unsupported_method",
            HostProtocolError::InvalidRequestId => "invalid_request_id",
            HostProtocolError::MalformedJson => "malformed_request",
            HostProtocolError::InvalidControlValue => "invalid_control_value",
            HostProtocolError::InvalidTarget => "invalid_target",
            HostProtocolError::UnsupportedTarget => "unsupported_target",
            other => panic!("unexpected classification: {other}"),
        }
    }

    #[test]
    fn session_name_rule_matches_shared_fixture() {
        let fixture = phase2_fixture("malformed-v1");
        let names = fixture.get("session_names").unwrap();
        for name in names.get("valid").unwrap().as_array().unwrap() {
            let name = name.as_str().unwrap();
            assert!(valid_session_name(name), "expected valid: {name:?}");
        }
        for name in names.get("invalid").unwrap().as_array().unwrap() {
            let name = name.as_str().unwrap();
            assert!(!valid_session_name(name), "expected invalid: {name:?}");
        }
        // Property-style hostile cases beyond the fixture list.
        assert!(!valid_session_name("\u{1f}"));
        assert!(!valid_session_name("a\u{0}b"));
        assert!(!valid_session_name(&"a".repeat(65)));
        assert!(valid_session_name(&"a".repeat(64)));
        assert!(!valid_session_name("=exact"));
        assert!(!valid_session_name("~home"));
    }

    #[test]
    fn a_push_ticket_registration_carries_a_ticket_and_nothing_describing_a_session() {
        let ticket = "T".repeat(140);
        let request = NotificationsRegisterRequest::new(REQUEST_ID.into(), Some(ticket.clone()));
        let encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            decode_rpc_request(&encoded).unwrap(),
            RpcRequest::NotificationsRegister(request)
        );
        // The only field on this method is the ticket. Nothing here can name a session, project,
        // or workspace, which is what keeps the relay unable to learn one (ADR 005).
        let params = serde_json::from_slice::<Value>(&encoded).unwrap()["params"].clone();
        assert_eq!(params, serde_json::json!({ "ticket": ticket }));

        // Revocation is the absent ticket, and it round-trips as such.
        let revoke = NotificationsRegisterRequest::new(REQUEST_ID.into(), None);
        assert_eq!(
            decode_rpc_request(&serde_json::to_vec(&revoke).unwrap()).unwrap(),
            RpcRequest::NotificationsRegister(revoke)
        );

        for hostile in [
            "",
            "short",
            &"T".repeat(513),
            &format!("{}=", "T".repeat(139)),
        ] {
            let mut request = NotificationsRegisterRequest::new(REQUEST_ID.into(), None);
            request.params.ticket = Some(hostile.to_string());
            assert!(
                matches!(
                    decode_rpc_request(&serde_json::to_vec(&request).unwrap()),
                    Err(HostProtocolError::InvalidControlValue)
                ),
                "{hostile}"
            );
        }
        assert!(valid_push_ticket(&ticket));
    }

    #[test]
    fn a_registration_response_says_whether_a_ticket_is_held_without_echoing_it() {
        let ticket = "T".repeat(140);
        for registered in [true, false] {
            let response = NotificationsRegisterResponse::new(REQUEST_ID.into(), registered);
            let encoded = serde_json::to_vec(&response).unwrap();
            assert!(!String::from_utf8_lossy(&encoded).contains(&ticket));
            let NotificationsRpcResponse::Registered(decoded) =
                decode_notifications_response(&encoded).unwrap()
            else {
                panic!("expected a registration response");
            };
            assert_eq!(decoded, response);
            assert_eq!(decoded.result.registered, registered);
        }

        let error = RpcErrorResponse::new(
            Some(REQUEST_ID.into()),
            "authorization_denied",
            "This installation is no longer authorized.",
        );
        assert!(matches!(
            decode_notifications_response(&serde_json::to_vec(&error).unwrap()).unwrap(),
            NotificationsRpcResponse::Error(_)
        ));
    }

    #[test]
    fn live_activity_registration_is_an_opaque_id_mutation_only() {
        let ticket = "T".repeat(140);
        let request = LiveActivityRegisterRequest::new(
            REQUEST_ID.into(),
            Some(ticket.clone()),
            Some(LiveActivitySelectionMutation {
                session_id: "agent-session-1".into(),
                enabled: true,
            }),
        );
        let encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            decode_rpc_request(&encoded).unwrap(),
            RpcRequest::LiveActivityRegister(request)
        );
        let params = serde_json::from_slice::<Value>(&encoded).unwrap()["params"].clone();
        assert_eq!(
            params,
            serde_json::json!({
                "ticket": ticket,
                "selection": { "session_id": "agent-session-1", "enabled": true }
            })
        );
        let text = String::from_utf8(encoded).unwrap();
        for forbidden in ["workspace", "host", "state", "prompt", "title"] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }

        // Token rotation carries no mutation; clear carries neither. Both are strict, distinct
        // operations and a mutation without a ticket is never accepted.
        for request in [
            LiveActivityRegisterRequest::new(REQUEST_ID.into(), Some("T".repeat(140)), None),
            LiveActivityRegisterRequest::new(REQUEST_ID.into(), None, None),
        ] {
            assert!(decode_rpc_request(&serde_json::to_vec(&request).unwrap()).is_ok());
        }
        let mutation_without_ticket = LiveActivityRegisterRequest::new(
            REQUEST_ID.into(),
            None,
            Some(LiveActivitySelectionMutation {
                session_id: "agent-session-1".into(),
                enabled: false,
            }),
        );
        assert!(matches!(
            decode_rpc_request(&serde_json::to_vec(&mutation_without_ticket).unwrap()),
            Err(HostProtocolError::InvalidControlValue)
        ));
        for session_id in ["", "../secret", &"a".repeat(65)] {
            let request = LiveActivityRegisterRequest::new(
                REQUEST_ID.into(),
                Some("T".repeat(140)),
                Some(LiveActivitySelectionMutation {
                    session_id: session_id.into(),
                    enabled: true,
                }),
            );
            assert!(matches!(
                decode_rpc_request(&serde_json::to_vec(&request).unwrap()),
                Err(HostProtocolError::InvalidControlValue)
            ));
        }
    }

    #[test]
    fn live_activity_response_bounds_and_correlates_the_selected_count() {
        for selected in 0..=MAX_LIVE_ACTIVITY_SELECTIONS {
            let response = LiveActivityRegisterResponse::new(REQUEST_ID.into(), selected);
            let encoded = serde_json::to_vec(&response).unwrap();
            let LiveActivityRpcResponse::Registered(decoded) =
                decode_live_activity_response(&encoded).unwrap()
            else {
                panic!("expected live activity registration response");
            };
            assert_eq!(decoded.result.selected_sessions, selected as u8);
            assert_eq!(decoded.result.registered, selected > 0);
        }
        let mut invalid = LiveActivityRegisterResponse::new(REQUEST_ID.into(), 2);
        invalid.result.registered = false;
        assert!(matches!(
            decode_live_activity_response(&serde_json::to_vec(&invalid).unwrap()),
            Err(HostProtocolError::InvalidControlValue)
        ));
    }

    #[test]
    fn workspace_snapshot_fixture_is_golden() {
        let fixture = phase2_fixture("workspace-snapshot-v1");
        let request_body = serde_json::to_vec(fixture.get("request").unwrap()).unwrap();
        let decoded = decode_rpc_request(&request_body).unwrap();
        assert_eq!(
            decoded,
            RpcRequest::WorkspaceSnapshot(WorkspaceSnapshotRequest::new(REQUEST_ID.into()))
        );

        let responses = fixture.get("responses").unwrap().as_object().unwrap();
        for (name, response) in responses {
            let body = serde_json::to_vec(response).unwrap();
            let decoded = decode_snapshot_response(&body).unwrap();
            let SnapshotRpcResponse::Snapshot(snapshot) = decoded else {
                panic!("expected snapshot response for {name}");
            };
            match name.as_str() {
                "full" => {
                    let tmux = snapshot.result.providers.tmux;
                    assert_eq!(tmux.state, PROVIDER_STATE_AVAILABLE);
                    assert_eq!(tmux.version.as_deref(), Some("3.6b"));
                    let sessions = tmux.sessions.unwrap();
                    assert_eq!(sessions.len(), 2);
                    assert_eq!(
                        sessions[0],
                        TmuxSessionEntry {
                            name: "api".into(),
                            attached: true,
                            windows: 3,
                            created_unix: 1_789_000_000,
                            tabs: None,
                        }
                    );
                    let herdr = snapshot.result.providers.herdr;
                    assert_eq!(
                        herdr.sessions.unwrap()[0],
                        HerdrSessionEntry {
                            name: "default".into(),
                            running: true,
                            is_default: true,
                            tabs: None,
                        }
                    );
                    assert_eq!(snapshot.result.omitted_sessions, 0);
                }
                "empty" => {
                    assert_eq!(
                        snapshot.result.providers.tmux.sessions.as_deref(),
                        Some(&[][..])
                    );
                }
                "degraded" => {
                    assert_eq!(snapshot.result.providers.tmux.state, PROVIDER_STATE_ERROR);
                    assert!(snapshot.result.providers.tmux.sessions.is_none());
                    assert_eq!(
                        snapshot.result.providers.herdr.state,
                        PROVIDER_STATE_NOT_INSTALLED
                    );
                    assert!(snapshot.result.providers.herdr.version.is_none());
                }
                "unsupported" => {
                    assert_eq!(
                        snapshot.result.providers.tmux.state,
                        PROVIDER_STATE_UNSUPPORTED_VERSION
                    );
                    assert_eq!(snapshot.result.omitted_sessions, 2);
                }
                other => panic!("unexpected fixture response {other}"),
            }
        }

        let errors = fixture.get("errors").unwrap().as_object().unwrap();
        for (name, error) in errors {
            let body = serde_json::to_vec(error).unwrap();
            let SnapshotRpcResponse::Error(decoded) = decode_snapshot_response(&body).unwrap()
            else {
                panic!("expected error response for {name}");
            };
            assert_eq!(&decoded.error.code, name);
        }

        let capabilities: Vec<String> = fixture
            .get("capabilities")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();
        let hello =
            HostHelloResponse::new(REQUEST_ID.into(), HOST_ID.into(), INSTALLATION_ID.into());
        assert!(
            capabilities
                .iter()
                .all(|capability| hello.result.capabilities.contains(capability))
        );
        assert!(
            hello
                .result
                .capabilities
                .contains(&CAPABILITY_AGENT_SESSION.into())
        );
        assert!(
            hello
                .result
                .capabilities
                .contains(&CAPABILITY_TERMINAL_AGENT_ROUTE.into())
        );
        assert!(
            hello
                .result
                .capabilities
                .contains(&CAPABILITY_AGENT_SESSION_MANAGED.into())
        );
        hello.validate().unwrap();
        validate_capabilities(&capabilities).unwrap();
    }

    #[test]
    fn phase2_malformed_fixture_cases_fail_as_declared() {
        let fixture = phase2_fixture("malformed-v1");
        for case in fixture
            .get("snapshot_requests")
            .unwrap()
            .as_array()
            .unwrap()
        {
            let json = case.get("json").unwrap().as_str().unwrap();
            let expected = case.get("error").unwrap().as_str().unwrap();
            let name = case.get("name").unwrap().as_str().unwrap();
            let error = decode_rpc_request(json.as_bytes()).unwrap_err();
            assert_eq!(classify(&error), expected, "case {name}");
        }
        for case in fixture.get("snapshot_results").unwrap().as_array().unwrap() {
            let json = case.get("json").unwrap().as_str().unwrap();
            let expected = case.get("error").unwrap().as_str().unwrap();
            let name = case.get("name").unwrap().as_str().unwrap();
            let error = decode_snapshot_response(json.as_bytes()).unwrap_err();
            assert_eq!(classify(&error), expected, "case {name}");
        }
        for case in fixture.get("open_frames").unwrap().as_array().unwrap() {
            let json = case.get("json").unwrap().as_str().unwrap();
            let expected = case.get("error").unwrap().as_str().unwrap();
            let name = case.get("name").unwrap().as_str().unwrap();
            let error = decode_terminal_frame(0x01, json.as_bytes()).unwrap_err();
            assert_eq!(classify(&error), expected, "case {name}");
        }
    }

    #[test]
    fn terminal_open_target_fixture_round_trips_with_exact_wire_targets() {
        let fixture = phase2_fixture("terminal-targets-v1");
        let mut seen = Vec::new();
        for case in fixture.get("open_frames").unwrap().as_array().unwrap() {
            let name = case.get("name").unwrap().as_str().unwrap();
            let payload = serde_json::to_vec(case.get("payload").unwrap()).unwrap();
            let frame = decode_terminal_frame(0x01, &payload).unwrap();
            let TerminalFrame::Open(open) = &frame else {
                panic!("expected open frame for {name}");
            };
            let target = open.validated_target().unwrap();
            seen.push(target);
            let (expected_target, expected_session) = match name {
                "shell" => (TerminalTarget::Shell, None),
                "tmux_attach" => (TerminalTarget::TmuxAttach, Some("api")),
                "tmux_create" => (TerminalTarget::TmuxCreate, Some("new-work")),
                "herdr_attach" => (TerminalTarget::HerdrAttach, Some("default")),
                "herdr_create" => (TerminalTarget::HerdrCreate, Some("box_1")),
                other => panic!("unexpected fixture frame {other}"),
            };
            assert_eq!(target, expected_target);
            assert_eq!(open.session.as_deref(), expected_session);
            assert_eq!(open.target, target.wire());
            let encoded = encode_terminal_frame(&frame).unwrap();
            let reparsed = decode_terminal_frame(0x01, &encoded[5..]).unwrap();
            assert_eq!(reparsed, frame);
        }
        assert_eq!(seen.len(), 5);
    }

    fn phase9_fixture() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase9/terminal-commands-v1.json"
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    /// The shared fixture is the wire contract both languages decode. Rows seeded from a live
    /// read of the pinned pair round-trip byte for byte, and an empty list is a legal answer
    /// rather than a degraded one — it is what the host sends for every reason it cannot vouch
    /// for a list.
    #[test]
    fn terminal_commands_fixture_round_trips_including_the_empty_answer() {
        let fixture = phase9_fixture();

        let request: TerminalCommandsRequest =
            serde_json::from_value(fixture["request"].clone()).unwrap();
        assert_eq!(request.validated_provider().unwrap(), ProviderKind::Herdr);
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            fixture["request"],
            "the request re-encodes to the fixture byte for byte"
        );
        // The same request the app builds from its own values must be that frame.
        assert_eq!(
            TerminalCommandsRequest::new(
                request.request_id.clone(),
                TerminalTarget::HerdrAttach,
                "default".into(),
            ),
            request
        );

        let response: TerminalCommandsResponse =
            serde_json::from_value(fixture["response"].clone()).unwrap();
        response.validate().unwrap();
        assert_eq!(response.result.commands.len(), 5);
        assert_eq!(response.result.commands[0].name, "compact");
        // The vendor's own aliases, carried rather than dropped: `/cost` and `/stats` are how a
        // person reaches `/usage`, and discarding them made 59 of 136 commands unfindable.
        assert_eq!(response.result.commands[1].name, "usage");
        assert_eq!(response.result.commands[1].aliases, ["cost", "stats"]);
        assert!(!response.result.commands[1].terminal);
        // The hand-kept row the vendor advertises nowhere. Marked, so a phone can say so.
        assert_eq!(response.result.commands[4].name, "exit");
        assert!(response.result.commands[4].terminal);
        assert_eq!(
            response.result.commands[0].hint,
            "<optional custom summarization instructions>"
        );
        assert_eq!(
            response.result.commands[3],
            crate::slash_commands::SlashCommand {
                name: "context".into(),
                hint: String::new(),
                description: String::new(),
                aliases: Vec::new(),
                terminal: false,
            },
            "absent hint and description decode as empty, and re-encode as absent"
        );
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            fixture["response"]
        );

        let empty: TerminalCommandsResponse =
            serde_json::from_value(fixture["empty_response"].clone()).unwrap();
        empty.validate().unwrap();
        assert!(empty.result.commands.is_empty());
        assert_eq!(
            serde_json::to_value(&empty).unwrap(),
            fixture["empty_response"]
        );
    }

    /// Both directions fail closed on the cases the fixture names, and each one is named there
    /// with the reason it is refused.
    #[test]
    fn terminal_commands_refuses_every_hostile_frame_the_fixture_names() {
        let fixture = phase9_fixture();

        for case in fixture["refused_requests"].as_array().unwrap() {
            let request: TerminalCommandsRequest =
                serde_json::from_value(case["frame"].clone()).unwrap();
            assert!(
                request.validate().is_err(),
                "should be refused: {}",
                case["why"]
            );
            // The dispatcher must refuse it too, not just the type's own validate.
            let body = serde_json::to_vec(&case["frame"]).unwrap();
            assert!(
                decode_rpc_request(&body).is_err(),
                "the decoder should refuse it as well: {}",
                case["why"]
            );
        }

        for case in fixture["refused_responses"].as_array().unwrap() {
            let response: TerminalCommandsResponse =
                serde_json::from_value(case["frame"].clone()).unwrap();
            assert!(
                response.validate().is_err(),
                "should be refused: {}",
                case["why"]
            );
        }
    }

    /// The published list is bounded at the wire as well as where it was built, so neither side
    /// is trusting the other's arithmetic.
    #[test]
    fn terminal_commands_enforces_its_bounds_at_the_wire() {
        use crate::slash_commands::{
            MAX_COMMAND_DESCRIPTION_BYTES, MAX_COMMAND_HINT_BYTES, MAX_COMMAND_NAME_BYTES,
            MAX_SLASH_COMMANDS, SlashCommand,
        };
        let row = |name: &str| SlashCommand {
            name: name.into(),
            hint: String::new(),
            description: String::new(),
            aliases: Vec::new(),
            terminal: false,
        };

        validate_slash_commands(&vec![row("compact"); MAX_SLASH_COMMANDS]).unwrap();
        assert!(validate_slash_commands(&vec![row("compact"); MAX_SLASH_COMMANDS + 1]).is_err());
        assert!(validate_slash_commands(&[row(&"x".repeat(MAX_COMMAND_NAME_BYTES))]).is_ok());
        assert!(validate_slash_commands(&[row(&"x".repeat(MAX_COMMAND_NAME_BYTES + 1))]).is_err());

        let mut over_hint = row("compact");
        over_hint.hint = "h".repeat(MAX_COMMAND_HINT_BYTES + 1);
        assert!(validate_slash_commands(&[over_hint]).is_err());

        let mut over_description = row("compact");
        over_description.description = "d".repeat(MAX_COMMAND_DESCRIPTION_BYTES + 1);
        assert!(validate_slash_commands(&[over_description]).is_err());

        // Namespaced plugin commands are ordinary and must survive.
        validate_slash_commands(&[row("woz:woz-review"), row("cloudflare:build-mcp")]).unwrap();
    }

    /// A real command surface does not fit in one frame, and the count bound never noticed.
    ///
    /// This is the defect that made the picker never appear: the owner's Mac reports 136
    /// commands, they encode to ~18 KB against a 16 KB ceiling, and the send path discarded the
    /// error. Note that `terminal_commands_enforces_its_bounds_at_the_wire` above passes
    /// `MAX_SLASH_COMMANDS` rows happily — because its rows carry no hint and no description.
    /// Bare rows are what made a count-only bound look sufficient, so this one is built the way
    /// the vendor actually answers.
    #[test]
    fn a_real_command_surface_is_trimmed_to_fit_instead_of_being_dropped() {
        use crate::slash_commands::{MAX_SLASH_COMMANDS, SlashCommand};

        // Sized to the real thing: 136 rows encoding to ~18 KB, ~2 KB over the ceiling. Maximal
        // rows would be ~30 KB and would shed *every* description, which hides the property this
        // is really about — that shedding stops as soon as the frame fits.
        let surface: Vec<SlashCommand> = (0..136)
            .map(|index| SlashCommand {
                name: format!("plugin-namespace:command-{index:03}"),
                hint: String::new(),
                description: "d".repeat(80),
                aliases: Vec::new(),
                terminal: false,
            })
            .collect();
        let names: Vec<String> = surface.iter().map(|entry| entry.name.clone()).collect();
        validate_slash_commands(&surface).expect("every row is individually within bounds");

        let response =
            TerminalCommandsResponse::new("AAECAwQFBgcICQoLDA0ODw".to_string(), surface.clone());
        // The bug, stated as an assertion: this is what the send path used to call.
        assert!(
            matches!(encode_rpc(&response), Err(HostProtocolError::FrameTooLarge)),
            "a realistic surface must not fit, or this test is not reproducing the defect"
        );

        let (encoded, bounded) =
            encode_terminal_commands_response_bounded(response).expect("trimming must succeed");
        assert!(
            encoded.len() <= MAX_RPC_BODY,
            "trimmed frame is still {} bytes",
            encoded.len()
        );
        bounded
            .validate()
            .expect("the trimmed frame is still valid");

        // Every command survives: names are what get typed, so nothing is dropped while any
        // garnish remains to shed.
        assert_eq!(
            bounded
                .result
                .commands
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>(),
            names,
            "no command may be dropped while descriptions could still be shed"
        );
        // Shed from the end, so the vendor's own ordering decides who keeps prose, and shedding
        // stops the moment it fits rather than stripping the whole list.
        assert!(
            !bounded.result.commands[0].description.is_empty(),
            "the first command should keep its description"
        );
        assert!(
            bounded
                .result
                .commands
                .last()
                .unwrap()
                .description
                .is_empty(),
            "the last command should be the one that lost it"
        );
        let kept = bounded
            .result
            .commands
            .iter()
            .filter(|entry| !entry.description.is_empty())
            .count();
        assert!(
            kept > bounded.result.commands.len() / 2,
            "only {kept} of {} descriptions survived; shedding should stop once it fits",
            bounded.result.commands.len()
        );

        // When stripping every description and hint still will not fit, whole rows go — and the
        // result is a short list rather than no answer at all.
        let huge: Vec<SlashCommand> = (0..MAX_SLASH_COMMANDS)
            .map(|index| SlashCommand {
                name: format!("{index:0>60}"),
                hint: String::new(),
                description: String::new(),
                aliases: Vec::new(),
                terminal: false,
            })
            .collect();
        let (encoded, bounded) = encode_terminal_commands_response_bounded(
            TerminalCommandsResponse::new("AAECAwQFBgcICQoLDA0ODw".to_string(), huge),
        )
        .expect("dropping rows must still produce a frame");
        assert!(encoded.len() <= MAX_RPC_BODY);
        assert!(
            !bounded.result.commands.is_empty(),
            "a short list beats none"
        );
        assert!(bounded.result.commands.len() < MAX_SLASH_COMMANDS);
    }

    /// A host that predates the capability answers `unsupported_method`, which is what makes the
    /// app's gate meaningful rather than decorative.
    #[test]
    fn the_capability_is_advertised_and_the_hello_still_fits_its_bound() {
        let hello = HostHelloResponse::new(
            "AAECAwQFBgcICQoLDA0ODw".into(),
            "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6".into(),
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f".into(),
        );
        hello.validate().unwrap();
        assert!(
            hello
                .result
                .capabilities
                .contains(&CAPABILITY_TERMINAL_COMMANDS.to_owned())
        );
        assert!(
            hello.result.capabilities.len() <= MAX_CAPABILITY_ENTRIES,
            "the advertised list has outgrown the bound both sides validate"
        );
    }

    fn phase8_fixture() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase8/workspace-tabs-v1.json"
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    /// Spec 021 §3.3: the shared fixture is the wire contract both languages decode. The
    /// tab-bearing response round-trips exactly; the legacy response never grows a tab key.
    #[test]
    fn workspace_tabs_fixture_round_trips_and_legacy_stays_tab_free() {
        let fixture = phase8_fixture();
        let response: WorkspaceSnapshotResponse =
            serde_json::from_value(fixture.get("snapshot_response").unwrap().clone()).unwrap();
        response.validate().unwrap();
        let boxes = &response.result.providers.herdr.sessions.as_ref().unwrap()[1];
        let tabs = boxes.tabs.as_ref().unwrap();
        assert_eq!(tabs.len(), 3);
        assert!(tabs[1].focused);
        assert_eq!(tabs[1].status.as_deref(), Some("working"));
        let api = &response.result.providers.tmux.sessions.as_ref().unwrap()[0];
        assert_eq!(api.tabs.as_ref().unwrap()[1].label, "two words here");

        // The agent join, both providers. An annotated tab names its conversation; an
        // unannotated one stays exactly the shape a host without the join would send, which is
        // what lets the field ship without a capability of its own.
        assert_eq!(
            api.tabs.as_ref().unwrap()[1].agent_session_id.as_deref(),
            Some("session-a")
        );
        assert_eq!(api.tabs.as_ref().unwrap()[0].agent_session_id, None);
        assert_eq!(tabs[1].agent_session_id.as_deref(), Some("session-b"));
        assert_eq!(tabs[0].agent_session_id, None);
        assert!(
            !serde_json::to_string(&api.tabs.as_ref().unwrap()[0])
                .unwrap()
                .contains("agent_session_id"),
            "an unannotated tab must not grow the key"
        );

        let (encoded, kept) = encode_snapshot_response_bounded(response.clone()).unwrap();
        assert_eq!(kept, response, "nothing was dropped to fit");
        let reparsed = decode_snapshot_response(&encoded[4..]).unwrap();
        assert_eq!(reparsed, SnapshotRpcResponse::Snapshot(response));

        let legacy: WorkspaceSnapshotResponse =
            serde_json::from_value(fixture.get("snapshot_legacy_response").unwrap().clone())
                .unwrap();
        legacy.validate().unwrap();
        let encoded = serde_json::to_string(&legacy).unwrap();
        assert!(
            !encoded.contains("tabs"),
            "a legacy response must stay byte-compatible with strict old-app codecs"
        );
    }

    /// Spec 021 §3.2: `{}` params decode to a tab-free request, the opt-in decodes true, and
    /// the encoded legacy request never carries the key an old host would refuse.
    #[test]
    fn snapshot_params_gate_tabs_without_moving_legacy_bytes() {
        let request = WorkspaceSnapshotRequest::new(REQUEST_ID.into());
        assert!(!request.params.tabs);
        let encoded = encode_rpc(&request).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("tabs"));

        let empty = format!(
            r#"{{"v":1,"type":"request","request_id":"{REQUEST_ID}","method":"workspace.snapshot","params":{{}}}}"#
        );
        let RpcRequest::WorkspaceSnapshot(decoded) = decode_rpc_request(empty.as_bytes()).unwrap()
        else {
            panic!("expected snapshot request");
        };
        assert!(!decoded.params.tabs);

        let opted = format!(
            r#"{{"v":1,"type":"request","request_id":"{REQUEST_ID}","method":"workspace.snapshot","params":{{"tabs":true}}}}"#
        );
        let RpcRequest::WorkspaceSnapshot(decoded) = decode_rpc_request(opted.as_bytes()).unwrap()
        else {
            panic!("expected snapshot request");
        };
        assert!(decoded.params.tabs);

        let unknown = format!(
            r#"{{"v":1,"type":"request","request_id":"{REQUEST_ID}","method":"workspace.snapshot","params":{{"panes":true}}}}"#
        );
        assert!(decode_rpc_request(unknown.as_bytes()).is_err());
    }

    #[test]
    fn tab_grammar_pins_ids_labels_and_statuses() {
        for id in ["@1", "@1234567890", "wX:t19", "w0:t1", "a.b-c_d", "9"] {
            assert!(valid_tab_id(id), "{id}");
        }
        for id in [
            "",
            "@",
            ":lead",
            "-lead",
            "has space",
            "a;b",
            "=x",
            "tab\u{1f}",
        ] {
            assert!(!valid_tab_id(id), "{id:?}");
        }
        assert!(valid_tab_id(&"a".repeat(MAX_TAB_ID_BYTES)));
        assert!(!valid_tab_id(&"a".repeat(MAX_TAB_ID_BYTES + 1)));

        assert!(valid_tab_label("two words here"));
        assert!(valid_tab_label(&"x".repeat(MAX_TAB_LABEL_BYTES)));
        assert!(!valid_tab_label(&"x".repeat(MAX_TAB_LABEL_BYTES + 1)));
        assert!(!valid_tab_label(""));
        assert!(!valid_tab_label("tab\u{7}bell"));

        for status in ["working", "idle", "unknown", "agent_status"] {
            assert!(valid_tab_status(status), "{status}");
        }
        for status in ["", "Working", "so-so", "with space", "x1"] {
            assert!(!valid_tab_status(status), "{status:?}");
        }
        assert!(!valid_tab_status(&"s".repeat(MAX_TAB_STATUS_BYTES + 1)));
    }

    #[test]
    fn snapshot_validation_refuses_malformed_tab_shapes() {
        let fixture = phase8_fixture();
        let good: WorkspaceSnapshotResponse =
            serde_json::from_value(fixture.get("snapshot_response").unwrap().clone()).unwrap();
        let mutate = |edit: &dyn Fn(&mut Vec<SessionTabEntry>)| {
            let mut response = good.clone();
            let sessions = response.result.providers.herdr.sessions.as_mut().unwrap();
            edit(sessions[1].tabs.as_mut().unwrap());
            response.result.validate()
        };

        assert!(
            mutate(&|tabs| tabs.clear()).is_err(),
            "empty is spelled by omission"
        );
        assert!(
            mutate(&|tabs| {
                let extra = tabs[0].clone();
                for _ in 0..MAX_TABS_PER_SESSION {
                    tabs.push(extra.clone());
                }
            })
            .is_err()
        );
        assert!(
            mutate(&|tabs| tabs[0].focused = true).is_err(),
            "two focused"
        );
        assert!(mutate(&|tabs| tabs[0].id = "has space".into()).is_err());
        assert!(mutate(&|tabs| tabs[0].label = "\u{7}".into()).is_err());
        assert!(mutate(&|tabs| tabs[0].status = Some("Working".into())).is_err());
        good.result.validate().unwrap();
    }

    #[test]
    fn tab_bearing_open_frames_round_trip_and_refusals_hold() {
        let fixture = phase8_fixture();
        for case in fixture.get("open_frames").unwrap().as_array().unwrap() {
            let name = case.get("name").unwrap().as_str().unwrap();
            let payload = serde_json::to_vec(case.get("payload").unwrap()).unwrap();
            let frame = decode_terminal_frame(0x01, &payload).unwrap();
            let TerminalFrame::Open(open) = &frame else {
                panic!("expected open frame for {name}");
            };
            open.validated_target().unwrap();
            assert!(open.tab.is_some(), "{name}");
            let encoded = encode_terminal_frame(&frame).unwrap();
            let reparsed = decode_terminal_frame(0x01, &encoded[5..]).unwrap();
            assert_eq!(reparsed, frame, "{name}");
        }
        for case in fixture
            .get("invalid_open_frames")
            .unwrap()
            .as_array()
            .unwrap()
        {
            let name = case.get("name").unwrap().as_str().unwrap();
            let payload = serde_json::to_vec(case.get("payload").unwrap()).unwrap();
            let refused = decode_terminal_frame(0x01, &payload).and_then(|frame| {
                let TerminalFrame::Open(open) = &frame else {
                    return Ok(());
                };
                open.validated_target().map(|_| ())
            });
            assert!(refused.is_err(), "{name} must be refused");
        }
    }

    /// Spec 021 §6: over the 16KB bound, the longest tab listing is shortened first, then whole
    /// listings go — herdr from the end of the list, tmux oldest-first — and only then do
    /// sessions drop. Every one of those is degradation, so `omitted_sessions` never moves.
    ///
    /// The shortening stage is the one that matters in practice (2026-08-25): the shape that
    /// overruns 16KB is one herdr session carrying a hundred-odd tabs, and nulling its listing
    /// would leave exactly the empty list the workspace level exists to fix.
    #[test]
    fn bounded_encoder_shortens_a_long_listing_before_it_nulls_one() {
        let long_session = HerdrSessionEntry {
            name: "boxes".into(),
            running: true,
            is_default: true,
            tabs: Some(
                (0..MAX_TABS_PER_SESSION)
                    .map(|index| SessionTabEntry {
                        id: format!("w0:t{index}"),
                        label: "l".repeat(MAX_TAB_LABEL_BYTES),
                        focused: index == 0,
                        status: Some("working".into()),
                        agent_session_id: None,
                        workspace: Some("w".repeat(MAX_TAB_LABEL_BYTES)),
                    })
                    .collect(),
            ),
        };
        let response = WorkspaceSnapshotResponse::new(
            REQUEST_ID.into(),
            WorkspaceSnapshotResult {
                v: 1,
                providers: WorkspaceProviders {
                    tmux: TmuxProviderSnapshot {
                        state: PROVIDER_STATE_AVAILABLE.into(),
                        version: Some("3.7b".into()),
                        sessions: Some(Vec::new()),
                    },
                    herdr: HerdrProviderSnapshot {
                        state: PROVIDER_STATE_AVAILABLE.into(),
                        version: Some("0.8.0".into()),
                        sessions: Some(vec![long_session]),
                    },
                },
                omitted_sessions: 0,
            },
        );
        let (encoded, kept) = encode_snapshot_response_bounded(response).unwrap();
        assert!(encoded.len() <= 4 + MAX_RPC_BODY);
        let tabs = kept.result.providers.herdr.sessions.as_ref().unwrap()[0]
            .tabs
            .as_ref()
            .expect("a listing too long to send is shortened, never nulled");
        assert!(tabs.len() < MAX_TABS_PER_SESSION, "it really was shortened");
        assert!(tabs.len() > 1, "and not shortened to nothing");
        // The cut comes off the end, so the provider's order survives it.
        assert_eq!(tabs[0].id, "w0:t0");
        assert_eq!(tabs[1].id, "w0:t1");
        assert_eq!(
            kept.result.omitted_sessions, 0,
            "shortening is not omission"
        );
    }

    /// The stages behind the shortening one, reached by giving every session a listing there is
    /// nothing left to shorten.
    #[test]
    fn bounded_encoder_strips_tabs_before_it_drops_sessions() {
        let fat_tabs = || {
            Some(
                (0..1)
                    .map(|index| SessionTabEntry {
                        id: format!("w0:t{index}"),
                        label: "l".repeat(MAX_TAB_LABEL_BYTES),
                        focused: index == 0,
                        status: Some("working".into()),
                        agent_session_id: None,
                        workspace: Some("w".repeat(MAX_TAB_LABEL_BYTES)),
                    })
                    .collect(),
            )
        };
        // Enough sessions, each already down to a single maxed tab, that the frame overruns
        // with nothing left for the shortening stage to take.
        let herdr_sessions: Vec<HerdrSessionEntry> = (0..MAX_SESSIONS_PER_PROVIDER)
            .map(|index| HerdrSessionEntry {
                name: format!("h{index:0>62}"),
                running: true,
                is_default: index == 0,
                tabs: fat_tabs(),
            })
            .collect();
        let response = WorkspaceSnapshotResponse::new(
            REQUEST_ID.into(),
            WorkspaceSnapshotResult {
                v: 1,
                providers: WorkspaceProviders {
                    tmux: TmuxProviderSnapshot {
                        state: PROVIDER_STATE_AVAILABLE.into(),
                        version: Some("3.7b".into()),
                        sessions: Some(Vec::new()),
                    },
                    herdr: HerdrProviderSnapshot {
                        state: PROVIDER_STATE_AVAILABLE.into(),
                        version: Some("0.8.0".into()),
                        sessions: Some(herdr_sessions),
                    },
                },
                omitted_sessions: 0,
            },
        );
        let (encoded, kept) = encode_snapshot_response_bounded(response).unwrap();
        assert!(encoded.len() <= 4 + MAX_RPC_BODY);
        let sessions = kept.result.providers.herdr.sessions.as_ref().unwrap();
        assert_eq!(
            sessions.len(),
            MAX_SESSIONS_PER_PROVIDER,
            "no session was dropped"
        );
        assert_eq!(kept.result.omitted_sessions, 0, "stripping is not omission");
        assert!(
            sessions[0].tabs.is_some(),
            "the front of the list keeps its tabs"
        );
        assert!(
            sessions[MAX_SESSIONS_PER_PROVIDER - 1].tabs.is_none(),
            "stripping starts at the end"
        );
        let boundary = sessions
            .iter()
            .position(|session| session.tabs.is_none())
            .unwrap();
        assert!(
            sessions[boundary..]
                .iter()
                .all(|session| session.tabs.is_none()),
            "stripping is contiguous from the end"
        );

        // The tmux side strips by age: the oldest session loses its tabs first.
        let tmux_sessions: Vec<TmuxSessionEntry> = (0..MAX_SESSIONS_PER_PROVIDER as u64)
            .map(|index| TmuxSessionEntry {
                name: format!("s{index:0>62}"),
                attached: false,
                windows: 1,
                created_unix: 2_000_000_000 - index,
                tabs: fat_tabs().map(|tabs: Vec<SessionTabEntry>| {
                    tabs.into_iter()
                        .map(|tab| SessionTabEntry {
                            id: format!("@{index}"),
                            ..tab
                        })
                        .collect()
                }),
            })
            .collect();
        let response = WorkspaceSnapshotResponse::new(
            REQUEST_ID.into(),
            WorkspaceSnapshotResult {
                v: 1,
                providers: WorkspaceProviders {
                    tmux: TmuxProviderSnapshot {
                        state: PROVIDER_STATE_AVAILABLE.into(),
                        version: Some("3.7b".into()),
                        sessions: Some(tmux_sessions),
                    },
                    herdr: HerdrProviderSnapshot {
                        state: PROVIDER_STATE_AVAILABLE.into(),
                        version: Some("0.8.0".into()),
                        sessions: Some(Vec::new()),
                    },
                },
                omitted_sessions: 0,
            },
        );
        let (_, kept) = encode_snapshot_response_bounded(response).unwrap();
        let sessions = kept.result.providers.tmux.sessions.as_ref().unwrap();
        assert_eq!(sessions.len(), MAX_SESSIONS_PER_PROVIDER);
        assert_eq!(kept.result.omitted_sessions, 0);
        // Index 0 has the NEWEST created_unix in this construction, the last index the oldest.
        assert!(sessions[0].tabs.is_some(), "newest keeps tabs");
        assert!(
            sessions[MAX_SESSIONS_PER_PROVIDER - 1].tabs.is_none(),
            "oldest is stripped first"
        );
    }

    #[test]
    fn capability_entries_are_bounded_and_unknowns_are_tolerated() {
        validate_capabilities(&[
            "terminal.shell".into(),
            "workspace.snapshot".into(),
            "future.unknown".into(),
        ])
        .unwrap();
        assert!(validate_capabilities(&[]).is_err());
        assert!(validate_capabilities(&["workspace.snapshot".into()]).is_err());
        assert!(validate_capabilities(&vec!["terminal.shell".into(); 17]).is_err());
        assert!(validate_capabilities(&["terminal.shell".into(), "x".repeat(65)]).is_err());
        assert!(validate_capabilities(&["terminal.shell".into(), "with space".into()]).is_err());
        validate_capabilities(&vec!["terminal.shell".into(); 16]).unwrap();
    }

    #[test]
    fn snapshot_truncation_is_deterministic_and_counts_omitted_sessions() {
        let tmux_sessions: Vec<TmuxSessionEntry> = (0..64_u64)
            .map(|index| TmuxSessionEntry {
                name: format!("t{index:0>62}"),
                attached: false,
                windows: u32::MAX,
                created_unix: 18_446_744_073_709_000_000 + index,
                tabs: None,
            })
            .collect();
        let herdr_sessions: Vec<HerdrSessionEntry> = (0..64)
            .map(|index| HerdrSessionEntry {
                name: format!("h{index:0>62}"),
                running: false,
                is_default: false,
                tabs: None,
            })
            .collect();
        let response = WorkspaceSnapshotResponse::new(
            REQUEST_ID.into(),
            WorkspaceSnapshotResult {
                v: 1,
                providers: WorkspaceProviders {
                    tmux: TmuxProviderSnapshot {
                        state: PROVIDER_STATE_AVAILABLE.into(),
                        version: Some("3.6b".into()),
                        sessions: Some(tmux_sessions.clone()),
                    },
                    herdr: HerdrProviderSnapshot {
                        state: PROVIDER_STATE_AVAILABLE.into(),
                        version: Some("0.7.4".into()),
                        sessions: Some(herdr_sessions.clone()),
                    },
                },
                omitted_sessions: 0,
            },
        );
        assert!(matches!(
            encode_rpc(&response),
            Err(HostProtocolError::FrameTooLarge)
        ));
        let (encoded, bounded) = encode_snapshot_response_bounded(response.clone()).unwrap();
        assert!(encoded.len() <= MAX_RPC_BODY + 4);
        let kept_tmux = bounded.result.providers.tmux.sessions.clone().unwrap();
        let kept_herdr = bounded.result.providers.herdr.sessions.clone().unwrap();
        let dropped = 128 - kept_tmux.len() - kept_herdr.len();
        assert!(dropped > 0);
        assert_eq!(bounded.result.omitted_sessions as usize, dropped);
        // herdr sessions are dropped from the end of the list before any tmux session.
        assert_eq!(kept_tmux, tmux_sessions);
        assert_eq!(kept_herdr, herdr_sessions[..kept_herdr.len()]);
        // Deterministic: a second run produces byte-identical output.
        let (encoded_again, _) = encode_snapshot_response_bounded(response).unwrap();
        assert_eq!(encoded, encoded_again);
        decode_snapshot_response(&encoded[4..]).unwrap();
    }

    #[test]
    fn unknown_rpc_method_classification_is_stable() {
        let body = br#"{"v":1,"type":"request","request_id":"AAECAwQFBgcICQoLDA0ODw","method":"shell.exec","params":{"min_protocol":1,"max_protocol":1}}"#;
        assert!(matches!(
            decode_rpc_request(body),
            Err(HostProtocolError::UnsupportedMethod)
        ));
        let no_method =
            br#"{"v":1,"type":"request","request_id":"AAECAwQFBgcICQoLDA0ODw","params":{}}"#;
        assert!(matches!(
            decode_rpc_request(no_method),
            Err(HostProtocolError::MalformedJson)
        ));
    }
}
