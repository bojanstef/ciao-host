//! Adapter-neutral Agent Session v1 model and bounded wire framing (Spec 005).
//!
//! This module intentionally contains no adapter payloads. Text is untrusted display content,
//! every command is a fixed canonical operation, and all extensible unions retain an explicit
//! `Unknown` case rather than defaulting to an authoritative state.

use std::io;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const AGENT_PROTOCOL_VERSION: u8 = 1;
pub const CAPABILITY_AGENT_SESSION_V1: &str = "agent.session.v1";
pub const CAPABILITY_AGENT_SESSION_MANAGED_V1: &str = "agent.session.managed.v1";
/// Spec 013: the pick-up verb for an unheld Codex conversation. A peer that never advertises
/// it sees the unheld rows — they are ordinary attached descriptors — but has no verb to
/// adopt one, which degrades quietly instead of breaking.
pub const CAPABILITY_AGENT_SESSION_ADOPTED_V1: &str = "agent.session.adopted.v1";
pub const CAPABILITY_TERMINAL_AGENT_ROUTE: &str = "terminal.agent_route.v1";
pub const MAX_AGENT_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_AGENT_LIST_BYTES: usize = 256 * 1024;
pub const MAX_AGENT_SESSIONS: usize = 64;
pub const MAX_TIMELINE_PAGE_ENTRIES: usize = 64;
pub const MAX_TIMELINE_PAGE_BYTES: usize = 256 * 1024;
pub const MAX_LIVE_TEXT_DELTA_BYTES: usize = 16 * 1024;
pub const MAX_AGENT_OUTBOUND_QUEUE_BYTES: usize = 1024 * 1024;
pub const MAX_PROMPT_BYTES: usize = 32 * 1024;
pub const MAX_PENDING_INTERACTIONS: usize = 16;
pub const MAX_QUESTIONS: usize = 8;
pub const MAX_OPTIONS_PER_QUESTION: usize = 16;
pub const MAX_TOOL_INPUT_PREVIEW_BYTES: usize = 16 * 1024;
pub const MAX_TOOL_RESULT_PREVIEW_BYTES: usize = 32 * 1024;
pub const MAX_COMMAND_RECEIPTS: usize = 128;
pub const MAX_TOKEN_BYTES: usize = 64;
pub const MAX_OPAQUE_ID_BYTES: usize = 64;
pub const MAX_WORKSPACE_DISPLAY_BYTES: usize = 256;
pub const MAX_RECENT_PROMPT_BYTES: usize = 200;
pub const MAX_RESUME_COMMAND_BYTES: usize = 128;
/// The model catalogue an adapter may publish, bounded so a vendor list cannot grow the snapshot
/// without a decision here. A catalogue is a menu, not a database: sixteen rows is more than any
/// pinned vendor offers today, and a longer one is refused rather than truncated so nobody is
/// shown a picker that quietly omits what they were looking for.
pub const MAX_MODEL_CATALOGUE_ENTRIES: usize = 16;
/// Wider than [`MAX_TOKEN_BYTES`]'s grammar allows for, because a model id is vendor-shaped:
/// `claude-opus-5[1m]` is a real one and the token grammar rejects its brackets.
pub const MAX_MODEL_ID_BYTES: usize = 64;
pub const MAX_MODEL_DISPLAY_NAME_BYTES: usize = 48;
/// Effort levels one model offers. The pinned SDK publishes five; the slack is for a vendor
/// adding one, not for an unbounded list.
pub const MAX_EFFORT_LEVELS_PER_MODEL: usize = 8;

/// Whether a running adapter build is covered by what conformance actually tested.
///
/// Equality was the old rule and it answered the wrong question: "is this the exact build we
/// ran the suite against", when what matters is "is the surface we use still the one we
/// tested". A patch release inside the tested minor is the one case where the vendor has
/// stated no interface changed, so it is accepted; an older patch is not, because the tested
/// build may rely on something introduced after it.
///
/// A minor or major bump still gates. Under SemVer a 0.x minor is a breaking change by
/// convention, and both adapters are pre-1.0 — Pi 0.81 → 0.82 is exactly the case this must
/// keep refusing.
///
/// This is a coarse instrument either way: it trusts the vendor's own version discipline. The
/// durable answer is for an adapter to detect the surfaces it needs at runtime and advertise
/// from what it finds, which the Pi bridge now does for its command surface. A per-version
/// cache of probe verdicts was considered and deliberately not built: a cached verdict goes
/// stale silently, and silent staleness in a capability gate is indistinguishable from a
/// regression.
pub fn version_within_tested_minor(running: &str, tested: &str) -> bool {
    let (Some(running), Some(tested)) = (parse_version(running), parse_version(tested)) else {
        return false;
    };
    running.0 == tested.0 && running.1 == tested.1 && running.2 >= tested.2
}

/// Spec 017 §3: where a sighted vendor version stands against the tested pin.
///
/// `Grounded` is the floor rule above — the range conformance actually covered. `Ahead` is
/// past tested with the vendor's own additivity promise as the only evidence: a minor above
/// the pin **when the pin's major is ≥ 1**, because that is what SemVer promises there and
/// nothing more. A 0.x minor is a breaking change by convention (the doc comment above names
/// Pi 0.81 → 0.82 as the case that must keep refusing), so for a 0.x pin a minor stays
/// `Unsupported` until something stronger than a version string proves it — which is Spec 017
/// Phase 3's job, and where the fourth state, `carried`, will come from. A major bump is
/// `Unsupported` for every vendor: detection cannot see a surface that still exists and now
/// means something else, which is what a major announces.
///
/// The promise is derived from the tested pin itself rather than configured per vendor, so a
/// vendor crossing 1.0 changes its own rule and no constant needs to remember to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorVersionState {
    Grounded,
    /// Past tested, but a mechanical check proved every surface the adapter reads unchanged —
    /// the pin's grounding evidence carried to the new version (`codex_carry`, Spec 017 §4.3).
    /// Never produced by the classifier itself: only a prover upgrades to it.
    Carried,
    Ahead,
    Unsupported,
}

impl VendorVersionState {
    /// Whether the version is admitted at all — the drop-in successor to the old boolean
    /// gates. `Carried` and `Ahead` are admitted; what differs above the gate is evidence,
    /// labeling, and accounting.
    pub fn admitted(self) -> bool {
        !matches!(self, Self::Unsupported)
    }

    /// The wire token, used in `NormalizedRegistration::version_state` and the descriptor's
    /// drift note.
    pub fn token(self) -> &'static str {
        match self {
            Self::Grounded => "grounded",
            Self::Carried => "carried",
            Self::Ahead => "ahead",
            Self::Unsupported => "unsupported",
        }
    }
}

/// One minor past a pin, derived for tests so a must-be-refused case can never silently
/// invert when the pin catches up to a spelled literal (vendor-version-policy trap #3).
#[cfg(test)]
pub(crate) fn one_minor_past(pin: &str) -> String {
    let mut parts = pin.split('.').map(|part| part.parse::<u32>().unwrap());
    let (major, minor) = (parts.next().unwrap(), parts.next().unwrap());
    format!("{major}.{}.0", minor + 1)
}

/// The only band a prover may speak for (Spec 017 §3): a later minor of the tested major.
/// Majors stay refused everywhere no matter what any prover says — detection cannot see a
/// surface that still exists and now means something else — and below-floor versions are older
/// than the grounding, not newer.
pub fn later_minor_of_tested_major(running: &str, tested: &str) -> bool {
    match (parse_version(running), parse_version(tested)) {
        (Some(running), Some(tested)) => running.0 == tested.0 && running.1 > tested.1,
        _ => false,
    }
}

pub fn classify_vendor_version(running: &str, tested: &str) -> VendorVersionState {
    let (Some(running), Some(tested)) = (parse_version(running), parse_version(tested)) else {
        return VendorVersionState::Unsupported;
    };
    if running.0 != tested.0 {
        return VendorVersionState::Unsupported;
    }
    match running.1.cmp(&tested.1) {
        std::cmp::Ordering::Less => VendorVersionState::Unsupported,
        std::cmp::Ordering::Equal if running.2 >= tested.2 => VendorVersionState::Grounded,
        std::cmp::Ordering::Equal => VendorVersionState::Unsupported,
        std::cmp::Ordering::Greater if tested.0 >= 1 => VendorVersionState::Ahead,
        std::cmp::Ordering::Greater => VendorVersionState::Unsupported,
    }
}

/// The coarsest bound worth keeping: the vendor has not declared a breaking change.
///
/// An adapter that detects the surfaces it needs at runtime does not need the host to guess
/// from a version string, so for those the host only refuses what the vendor itself says is
/// incompatible. Detection cannot see a surface that still exists and now means something
/// else, which is what a major bump announces.
pub fn version_major_matches(running: &str, tested: &str) -> bool {
    match (parse_version(running), parse_version(tested)) {
        (Some(running), Some(tested)) => running.0 == tested.0,
        _ => false,
    }
}

/// Bounded `major.minor.patch`. A prerelease or build suffix makes this `None`, so an
/// unreleased build is never treated as covered by a tested release.
pub(crate) fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some((major, minor, patch))
}
pub const MAX_INTERACTION_TEXT_BYTES: usize = 32 * 1024;
pub const MAX_TIMELINE_TEXT_BYTES: usize = 48 * 1024;
pub const MAX_TIMELINE_ENTRIES_IN_SNAPSHOT: usize = 64;
pub const MAX_WORKSPACE_LIST_ENTRIES: usize = 64;
pub const MAX_WORKSPACE_LIST_BYTES: usize = 64 * 1024;
pub const MAX_WORKSPACE_LABEL_BYTES: usize = 128;
pub const MAX_LIFECYCLE_RECEIPTS: usize = 32;

#[derive(Debug, Error)]
pub enum AgentProtocolError {
    #[error("agent frame ended before a complete value")]
    Truncated,
    #[error("agent frame cannot be empty")]
    ZeroLength,
    #[error("agent frame exceeds its bound")]
    FrameTooLarge,
    #[error("agent frame contains malformed JSON")]
    MalformedJson,
    #[error("agent protocol version is unsupported")]
    UnsupportedVersion,
    #[error("agent value violates a protocol bound")]
    InvalidValue,
    #[error("agent message is invalid in this state")]
    UnexpectedMessage,
    #[error("agent stream I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub coverage: String,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_authoritative_at: Option<u64>,
}

impl Observation {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_token(&self.coverage)?;
        valid_token(&self.reason_code)?;
        Ok(())
    }

    pub fn is_authoritative(&self) -> bool {
        self.coverage == "authoritative"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandCapabilities {
    pub prompt: bool,
    pub steer: bool,
    pub follow_up: bool,
    pub interrupt: bool,
    /// Whether this adapter can change the session's permission mode while it runs. Defaulted
    /// rather than required, so an adapter written before the capability existed decodes as
    /// not offering it instead of failing to decode at all.
    #[serde(default)]
    pub permission_mode: bool,
    /// Whether this adapter can switch the model answering the conversation while it runs.
    /// Defaulted for the same reason as `permission_mode`: a host or adapter written before the
    /// capability existed decodes as not offering it rather than failing to decode.
    #[serde(default)]
    pub model: bool,
    /// Whether this adapter can change the reasoning effort. Separate from `model` because they
    /// are separately gated upstream — a model that supports no effort levels leaves this
    /// unusable while the model switch still works.
    #[serde(default)]
    pub effort: bool,
}

impl CommandCapabilities {
    pub const fn none() -> Self {
        Self {
            prompt: false,
            steer: false,
            follow_up: false,
            interrupt: false,
            permission_mode: false,
            model: false,
            effort: false,
        }
    }

    pub const fn permits(&self, kind: &AgentCommandKind) -> bool {
        match kind {
            AgentCommandKind::Prompt { .. } => self.prompt,
            AgentCommandKind::Steer { .. } => self.steer,
            AgentCommandKind::FollowUp { .. } => self.follow_up,
            AgentCommandKind::Interrupt => self.interrupt,
            AgentCommandKind::SetPermissionMode { .. } => self.permission_mode,
            AgentCommandKind::SetModel { .. } => self.model,
            AgentCommandKind::SetEffort { .. } => self.effort,
            AgentCommandKind::InteractionResponse { .. } | AgentCommandKind::Unknown => false,
        }
    }
}

/// Every permission mode Ciao will carry, which is exactly the pinned Claude SDK's own
/// `PermissionMode` union. Canonical here rather than beside either reader, because the same
/// list has to gate three things that would otherwise drift apart: what is read out of a
/// transcript, what a phone is allowed to ask for, and what is handed to a worker.
///
/// A mode outside it is refused rather than forwarded. A vendor adding one must not be able to
/// widen what a session may do without someone deciding to teach Ciao the word.
pub const KNOWN_PERMISSION_MODES: [&str; 6] = [
    "default",
    "acceptEdits",
    "bypassPermissions",
    "plan",
    "dontAsk",
    "auto",
];

pub fn valid_permission_mode(mode: &str) -> bool {
    KNOWN_PERMISSION_MODES.contains(&mode)
}

/// Model ids and effort levels are deliberately *not* given the treatment above.
///
/// A permission mode is a word Ciao defines: the list is finite, it decides what a session may
/// do, and a vendor must not be able to widen it without someone teaching Ciao the word. Model
/// ids are the opposite on every count. They are vendor-owned, they change under us between
/// releases with no say from here, and choosing one widens nothing — every model in a
/// catalogue is already something this account may run. Pinning them to a closed union here
/// would mean a model shipped on Tuesday is unusable until Ciao ships too, which is a worse
/// failure than the one a union prevents.
///
/// So both layers keep only what they can honestly own: this one checks grammar and bounds, and
/// the *vendor's* list is the authority on which ids exist — the worker refuses anything outside
/// the catalogue it read from the SDK, and the adapter refuses an effort level outside the pin.
/// That keeps the closed check where the closed knowledge actually lives.
///
/// The grammar is [`valid_token`]'s plus brackets, which real ids need: `claude-opus-5[1m]`.
pub fn valid_model_id(value: &str) -> Result<(), AgentProtocolError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_MODEL_ID_BYTES
        || !bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'[' | b']')
        })
    {
        return Err(AgentProtocolError::InvalidValue);
    }
    Ok(())
}

/// One row of the catalogue an adapter publishes, so the phone renders the models this host can
/// actually run instead of a list compiled into the app months ago.
///
/// `description` is deliberately dropped on the way in: it is prose of vendor length, it would
/// dominate the frame budget, and a picker row shows a name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentModelOption {
    pub value: String,
    pub display_name: String,
    #[serde(default)]
    pub supports_effort: bool,
    /// Empty when the model offers no effort choice. The phone shows an effort picker only for
    /// the active model's own levels, so a model that silently downgrades an unsupported level
    /// is never offered one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_effort_levels: Vec<String>,
}

impl AgentModelOption {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_model_id(&self.value)?;
        if self.display_name.is_empty()
            || self.display_name.len() > MAX_MODEL_DISPLAY_NAME_BYTES
            || self.supported_effort_levels.len() > MAX_EFFORT_LEVELS_PER_MODEL
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        for level in &self.supported_effort_levels {
            valid_token(level)?;
        }
        Ok(())
    }
}

/// A catalogue is a menu: bounded, and every row valid or none of it is.
pub fn validate_model_catalogue(models: &[AgentModelOption]) -> Result<(), AgentProtocolError> {
    if models.len() > MAX_MODEL_CATALOGUE_ENTRIES {
        return Err(AgentProtocolError::InvalidValue);
    }
    for model in models {
        model.validate()?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteractionCapability {
    pub enabled: bool,
    pub max_questions: u8,
    pub max_options_per_question: u8,
    pub allows_free_text: bool,
}

impl InteractionCapability {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        if usize::from(self.max_questions) > MAX_QUESTIONS
            || usize::from(self.max_options_per_question) > MAX_OPTIONS_PER_QUESTION
            || (!self.enabled
                && (self.max_questions != 0
                    || self.max_options_per_question != 0
                    || self.allows_free_text))
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        Ok(())
    }

    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            max_questions: 0,
            max_options_per_question: 0,
            allows_free_text: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteractionCapabilities {
    pub permission: InteractionCapability,
    pub question: InteractionCapability,
    pub plan_decision: InteractionCapability,
    pub review_decision: InteractionCapability,
    pub elicitation: InteractionCapability,
    pub generic_choice: InteractionCapability,
}

impl InteractionCapabilities {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        for capability in [
            &self.permission,
            &self.question,
            &self.plan_decision,
            &self.review_decision,
            &self.elicitation,
            &self.generic_choice,
        ] {
            capability.validate()?;
        }
        Ok(())
    }

    pub const fn none() -> Self {
        Self {
            permission: InteractionCapability::disabled(),
            question: InteractionCapability::disabled(),
            plan_decision: InteractionCapability::disabled(),
            review_decision: InteractionCapability::disabled(),
            elicitation: InteractionCapability::disabled(),
            generic_choice: InteractionCapability::disabled(),
        }
    }

    pub const fn any_enabled(&self) -> bool {
        self.permission.enabled
            || self.question.enabled
            || self.plan_decision.enabled
            || self.review_decision.enabled
            || self.elicitation.enabled
            || self.generic_choice.enabled
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCapabilities {
    pub history: String,
    pub commands: CommandCapabilities,
    pub interactions: InteractionCapabilities,
    pub pending_rehydration: String,
    pub terminal_continuity: String,
}

impl AgentCapabilities {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_token(&self.history)?;
        valid_token(&self.pending_rehydration)?;
        valid_token(&self.terminal_continuity)?;
        self.interactions.validate()?;
        Ok(())
    }

    /// Interaction responses are gated by interaction capabilities, not command
    /// capabilities; every other kind defers to `CommandCapabilities::permits`.
    pub const fn permits(&self, kind: &AgentCommandKind) -> bool {
        match kind {
            AgentCommandKind::InteractionResponse { .. } => self.interactions.any_enabled(),
            other => self.commands.permits(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalFallback {
    pub continuity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_reason: Option<String>,
    /// The provider session a released conversation was handed back to. Deliberately not
    /// `route_id`: that is an opaque handle into the attached supervisor's live-pane
    /// resolver, and a handback is a Phase 2 durable route — a provider session name the
    /// client already knows how to attach. Non-secret, and never a path or a vendor ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handback_session: Option<String>,
    /// The vendor command that reopens this conversation in whatever terminal the user
    /// actually uses — `claude --resume <id>`, `codex resume <id>`.
    ///
    /// The third route representation, and the only one that survives everything: a tmux
    /// handback dies with its session, an opaque resolver dies with the pane, but the vendor
    /// keeps the conversation and this reaches it from any shell. Ciao cannot type it for
    /// them, because which multiplexer they are in is not Ciao's to know; the phone copies it.
    ///
    /// This is the one place a vendor session ID crosses to a client. It is a local
    /// conversation name, not a credential, and withholding it is what left a released
    /// session reachable only from the machine the user is not at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_command: Option<String>,
}

impl TerminalFallback {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_token(&self.continuity)?;
        if let Some(route_id) = &self.route_id {
            valid_opaque_id(route_id)?;
        }
        if let Some(session) = &self.handback_session
            && !crate::host_protocol::valid_session_name(session)
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        if let Some(reason) = &self.availability_reason {
            valid_token(reason)?;
        }
        if let Some(command) = &self.resume_command {
            valid_resume_command(command)?;
        }
        let has_route_id = self.route_id.is_some();
        let has_handback = self.handback_session.is_some();
        let has_resume = self.resume_command.is_some();
        match self.continuity.as_str() {
            "exact_live" | "workspace_only" if !has_route_id || has_handback || has_resume => {
                Err(AgentProtocolError::InvalidValue)
            }
            // A live pane and a durable provider session are alternative claims about the same
            // terminal, so both together would be ambiguous. The resume command is not a
            // claim about a terminal at all — it is the conversation's own name — so it
            // accompanies either, and on its own it is the whole route.
            "resumable_session"
                if (has_route_id && has_handback)
                    || !(has_route_id || has_handback || has_resume) =>
            {
                Err(AgentProtocolError::InvalidValue)
            }
            "unavailable" if has_route_id || has_handback || has_resume => {
                Err(AgentProtocolError::InvalidValue)
            }
            // Unknown continuity stays explicit but cannot smuggle any route shape.
            value
                if !matches!(value, "exact_live" | "resumable_session" | "workspace_only")
                    && (has_route_id || has_handback || has_resume) =>
            {
                Err(AgentProtocolError::InvalidValue)
            }
            _ => Ok(()),
        }
    }
}

/// A literal command line for the user to paste, so the grammar is deliberately narrower than
/// a shell's: alphanumerics, `-`, `_`, `.` and the spaces between argv elements. No quote, no
/// slash, no separator, no newline — nothing that could turn a pasted line into two commands.
pub fn valid_resume_command(value: &str) -> Result<(), AgentProtocolError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_RESUME_COMMAND_BYTES
        || bytes.first() == Some(&b' ')
        || bytes.last() == Some(&b' ')
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b' '))
    {
        return Err(AgentProtocolError::InvalidValue);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionDescriptor {
    pub v: u8,
    pub session_id: String,
    pub adapter_family: String,
    pub adapter_version: String,
    pub topology: String,
    pub presence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_reason: Option<String>,
    pub process_generation: u64,
    pub observation: Observation,
    pub turn: TurnState,
    pub capabilities: AgentCapabilities,
    pub workspace_display: String,
    pub terminal_fallback: TerminalFallback,
    /// The turn-opening prompt in the user's own words, bounded and first-line only. The
    /// directory is otherwise pure metadata, which makes two sessions in one workspace
    /// indistinguishable; this is the smallest thing that says which conversation is which.
    /// Absent when the session has no user message yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_prompt: Option<String>,
    /// The managed session already running this attached session's conversation, when there is
    /// one. Ciao's own session ID, never the vendor's — the phone uses it to open the
    /// conversation where it actually lives instead of offering a takeover that has already
    /// happened. Absent on every other kind of row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_session_id: Option<String>,
    /// The takeover verb this row honestly offers: `promote` for an attached Claude
    /// conversation a managed worker can resume, `pickup` for an attached Codex conversation
    /// the daemon can adopt. Advertised by the host, which is where vendor knowledge lives,
    /// instead of re-derived from the family name on the phone — POSTMORTEMS records the bug
    /// that pattern shipped. Absent on every row with nothing to offer and absent from older
    /// hosts, so only presence grants the verb.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover: Option<String>,
    /// Present only while this row's vendor runs ahead of the host's grounding (Spec 017
    /// §4.5). Same additive contract as `takeover`: absent from older hosts, and only
    /// presence renders the line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift: Option<DriftNote>,
    pub revision: u64,
    pub updated_at: u64,
}

impl AgentSessionDescriptor {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        require_version(self.v)?;
        valid_opaque_id(&self.session_id)?;
        valid_token(&self.adapter_family)?;
        valid_token(&self.adapter_version)?;
        valid_token(&self.topology)?;
        valid_token(&self.presence)?;
        if self.process_generation == 0
            || self.revision == 0
            || self.updated_at == 0
            || self.workspace_display.is_empty()
            || self.workspace_display.len() > MAX_WORKSPACE_DISPLAY_BYTES
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        if let Some(prompt) = &self.recent_prompt
            && (prompt.is_empty() || prompt.len() > MAX_RECENT_PROMPT_BYTES)
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        // The verb's value stays decode-tolerant — a future verb renders as unsupported, not
        // as a refusal — but only an attached row may carry one at all: a managed or adopted
        // conversation is already Ciao's, and a takeover offer there is a fabrication.
        if let Some(takeover) = &self.takeover {
            valid_token(takeover)?;
            if self.topology != "attached" {
                return Err(AgentProtocolError::InvalidValue);
            }
        }
        if let Some(drift) = &self.drift {
            drift.validate()?;
        }
        self.observation.validate()?;
        self.turn.validate()?;
        self.capabilities.validate()?;
        self.terminal_fallback.validate()?;
        if self.capabilities.terminal_continuity != self.terminal_fallback.continuity {
            return Err(AgentProtocolError::InvalidValue);
        }
        validate_topology_presence(
            &self.topology,
            &self.presence,
            self.stored_reason.as_deref(),
            &self.turn,
            &self.capabilities,
        )?;
        Ok(())
    }
}

/// Spec 006 §6 invariants shared by descriptors and snapshots: a stored session
/// is managed-only, advertises no mutation, and cannot be mid-turn. Managed continuity
/// stays unavailable except for the explicitly released, one-way handback route.
/// Spec 013 §9 adds the adopted arm: an adopted session exists only while Ciao holds the
/// thread, so it is live-only, and its way back to a terminal is resuming the conversation —
/// `resumable_session`, never a claimed pane and never unavailable.
fn validate_topology_presence(
    topology: &str,
    presence: &str,
    stored_reason: Option<&str>,
    turn: &TurnState,
    capabilities: &AgentCapabilities,
) -> Result<(), AgentProtocolError> {
    if let Some(reason) = stored_reason {
        valid_token(reason)?;
        if presence != "stored" {
            return Err(AgentProtocolError::InvalidValue);
        }
    }
    if presence == "stored"
        && (topology != "managed"
            || matches!(
                turn,
                TurnState::Running { .. }
                    | TurnState::AwaitingInteraction { .. }
                    | TurnState::Stopping { .. }
            )
            || capabilities.commands != CommandCapabilities::none()
            || capabilities.interactions != InteractionCapabilities::none())
    {
        return Err(AgentProtocolError::InvalidValue);
    }
    if topology == "managed"
        && capabilities.terminal_continuity != "unavailable"
        && !(presence == "stored"
            && stored_reason == Some("released")
            && capabilities.terminal_continuity == "resumable_session")
    {
        return Err(AgentProtocolError::InvalidValue);
    }
    if topology == "adopted"
        && (presence != "live" || capabilities.terminal_continuity != "resumable_session")
    {
        return Err(AgentProtocolError::InvalidValue);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TurnState {
    Idle,
    Running {
        run_id: String,
        activity: String,
    },
    AwaitingInteraction {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_id: Option<String>,
    },
    Stopping {
        run_id: String,
    },
    Completed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_id: Option<String>,
    },
    Interrupted {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_id: Option<String>,
    },
    Failed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_id: Option<String>,
        category: String,
    },
    Unknown {
        reason_code: String,
    },
    #[serde(other)]
    Unsupported,
}

impl TurnState {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        match self {
            Self::Running { run_id, activity } => {
                valid_opaque_id(run_id)?;
                valid_token(activity)?;
            }
            Self::AwaitingInteraction { run_id }
            | Self::Completed { run_id }
            | Self::Interrupted { run_id } => {
                if let Some(run_id) = run_id {
                    valid_opaque_id(run_id)?;
                }
            }
            Self::Stopping { run_id } => valid_opaque_id(run_id)?,
            Self::Failed { run_id, category } => {
                if let Some(run_id) = run_id {
                    valid_opaque_id(run_id)?;
                }
                valid_token(category)?;
            }
            Self::Unknown { reason_code } => valid_token(reason_code)?,
            Self::Idle | Self::Unsupported => {}
        }
        Ok(())
    }

    pub const fn is_authoritative_working(&self) -> bool {
        matches!(self, Self::Running { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTimelineBody {
    pub name: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_preview: Option<String>,
}

impl ToolTimelineBody {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_token(&self.name)?;
        valid_token(&self.status)?;
        if self
            .input_preview
            .as_ref()
            .is_some_and(|value| value.len() > MAX_TOOL_INPUT_PREVIEW_BYTES)
            || self
                .result_preview
                .as_ref()
                .is_some_and(|value| value.len() > MAX_TOOL_RESULT_PREVIEW_BYTES)
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TimelineBody {
    Text {
        text: String,
    },
    Tool {
        tool: ToolTimelineBody,
    },
    Unsupported {
        reason_code: String,
    },
    #[serde(other)]
    Unknown,
}

impl TimelineBody {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        match self {
            Self::Text { text } if text.len() <= MAX_TIMELINE_TEXT_BYTES => Ok(()),
            Self::Text { .. } => Err(AgentProtocolError::InvalidValue),
            Self::Tool { tool } => tool.validate(),
            Self::Unsupported { reason_code } => valid_token(reason_code),
            Self::Unknown => Ok(()),
        }
    }

    pub fn decoded_bytes(&self) -> usize {
        match self {
            Self::Text { text } => text.len(),
            Self::Tool { tool } => {
                tool.name.len()
                    + tool.status.len()
                    + tool.input_preview.as_ref().map_or(0, String::len)
                    + tool.result_preview.as_ref().map_or(0, String::len)
            }
            Self::Unsupported { reason_code } => reason_code.len(),
            Self::Unknown => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Truncation {
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_bytes: Option<u64>,
}

impl Truncation {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        if let Some(reason) = &self.reason_code {
            valid_token(reason)?;
        }
        if self.truncated != self.reason_code.is_some() {
            return Err(AgentProtocolError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineEntry {
    pub entry_id: String,
    pub entry_revision: u64,
    pub sequence: u64,
    pub timestamp: u64,
    pub state: String,
    pub kind: String,
    pub body: TimelineBody,
    pub truncation: Truncation,
}

impl TimelineEntry {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_opaque_id(&self.entry_id)?;
        if self.entry_revision == 0 || self.sequence == 0 || self.timestamp == 0 {
            return Err(AgentProtocolError::InvalidValue);
        }
        valid_token(&self.state)?;
        valid_token(&self.kind)?;
        self.body.validate()?;
        self.truncation.validate()?;
        Ok(())
    }

    pub fn decoded_bytes(&self) -> usize {
        self.entry_id.len() + self.state.len() + self.kind.len() + self.body.decoded_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseChoice {
    pub choice_id: String,
    pub label: String,
    /// What choosing this means. Optional because a permission's two buttons need no gloss;
    /// a question's options are unanswerable without one, since the label is a noun phrase of
    /// one to five words and the consequence lives here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl ResponseChoice {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_opaque_id(&self.choice_id)?;
        if self.label.is_empty() || self.label.len() > 1024 {
            return Err(AgentProtocolError::InvalidValue);
        }
        if self
            .description
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_INTERACTION_TEXT_BYTES)
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        if let Some(scope) = &self.scope {
            valid_token(scope)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalQuestion {
    pub question_id: String,
    pub prompt: String,
    pub response_kind: String,
    pub required: bool,
    /// A short chip naming what the question is about, so several questions on one card are
    /// distinguishable without reading each one. Free text rather than a token: it is display
    /// copy chosen by the agent, and Ciao never decides what it says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    pub options: Vec<ResponseChoice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_text_bytes: Option<u32>,
}

impl CanonicalQuestion {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_opaque_id(&self.question_id)?;
        valid_token(&self.response_kind)?;
        if self
            .header
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_INTERACTION_TEXT_BYTES)
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        if self.prompt.is_empty()
            || self.prompt.len() > MAX_INTERACTION_TEXT_BYTES
            || self.options.len() > MAX_OPTIONS_PER_QUESTION
            || self.max_text_bytes.is_some_and(|value| {
                value == 0 || usize::try_from(value).unwrap_or(usize::MAX) > MAX_PROMPT_BYTES
            })
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        for option in &self.options {
            option.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseSchema {
    Choices {
        minimum: u8,
        maximum: u8,
        choices: Vec<ResponseChoice>,
    },
    Questions {
        questions: Vec<CanonicalQuestion>,
    },
    FreeText {
        maximum_bytes: u32,
    },
    Unsupported,
    #[serde(other)]
    Unknown,
}

impl ResponseSchema {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        match self {
            Self::Choices {
                minimum,
                maximum,
                choices,
            } => {
                if choices.is_empty()
                    || choices.len() > MAX_OPTIONS_PER_QUESTION
                    || minimum > maximum
                    || usize::from(*maximum) > choices.len()
                {
                    return Err(AgentProtocolError::InvalidValue);
                }
                for choice in choices {
                    choice.validate()?;
                }
            }
            Self::Questions { questions } => {
                if questions.is_empty() || questions.len() > MAX_QUESTIONS {
                    return Err(AgentProtocolError::InvalidValue);
                }
                for question in questions {
                    question.validate()?;
                }
            }
            Self::FreeText { maximum_bytes } => {
                if *maximum_bytes == 0
                    || usize::try_from(*maximum_bytes).unwrap_or(usize::MAX) > MAX_PROMPT_BYTES
                {
                    return Err(AgentProtocolError::InvalidValue);
                }
            }
            Self::Unsupported | Self::Unknown => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingInteraction {
    pub interaction_id: String,
    pub interaction_revision: u64,
    pub kind: String,
    pub blocking: bool,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub body: String,
    pub response_schema: ResponseSchema,
    pub terminal_fallback: TerminalFallback,
    pub state: String,
}

impl PendingInteraction {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_opaque_id(&self.interaction_id)?;
        valid_token(&self.kind)?;
        valid_token(&self.state)?;
        if self.interaction_revision == 0
            || self.created_at == 0
            || self.expires_at.is_some_and(|value| value < self.created_at)
            || self
                .title
                .as_ref()
                .is_some_and(|value| value.len() > MAX_INTERACTION_TEXT_BYTES)
            || self.body.len() > MAX_INTERACTION_TEXT_BYTES
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        self.response_schema.validate()?;
        self.terminal_fallback.validate()?;
        Ok(())
    }

    pub fn is_unresolved_blocking(&self) -> bool {
        self.blocking && matches!(self.state.as_str(), "pending" | "submitting")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandReceipt {
    pub command_id: String,
    pub session_id: String,
    pub process_generation: u64,
    pub snapshot_epoch: u64,
    pub state: String,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_evidence: Option<String>,
}

impl CommandReceipt {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_opaque_id(&self.command_id)?;
        valid_opaque_id(&self.session_id)?;
        valid_token(&self.state)?;
        if self.process_generation == 0 || self.snapshot_epoch == 0 || self.updated_at == 0 {
            return Err(AgentProtocolError::InvalidValue);
        }
        if let Some(reason) = &self.reason_code {
            valid_token(reason)?;
        }
        if let Some(evidence) = &self.application_evidence {
            valid_token(evidence)?;
        }
        if self.state == "applied" && self.application_evidence.is_none() {
            return Err(AgentProtocolError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineWindow {
    pub entries: Vec<TimelineEntry>,
    pub has_older: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_boundary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub newest_sequence: Option<u64>,
    pub truncated: bool,
}

impl TimelineWindow {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        if self.entries.len() > MAX_TIMELINE_ENTRIES_IN_SNAPSHOT {
            return Err(AgentProtocolError::InvalidValue);
        }
        if let Some(boundary) = &self.history_boundary {
            valid_token(boundary)?;
        }
        let mut last = None;
        for entry in &self.entries {
            entry.validate()?;
            if last.is_some_and(|sequence| sequence >= entry.sequence) {
                return Err(AgentProtocolError::InvalidValue);
            }
            last = Some(entry.sequence);
        }
        if let Some(first) = self.entries.first()
            && self.oldest_sequence != Some(first.sequence)
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        if let Some(last) = self.entries.last()
            && self.newest_sequence != Some(last.sequence)
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        if self.entries.is_empty()
            && (self.oldest_sequence.is_some() || self.newest_sequence.is_some())
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        Ok(())
    }
}

/// Spec 017 §4.5: the one-line truth about a vendor running past this build's grounding.
/// Rides descriptors and snapshots as an additive optional — absent from older hosts and from
/// every grounded session, so only presence renders anything — while `compatibility` keeps its
/// existing tokens: an `ahead` session *is* compatible-with-accounting, and letting an old app
/// degrade it to the unsupported banner would be the lie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftNote {
    /// `ahead`; `carried` once a prover vouched; `unsupported` only alongside a known `fix`,
    /// where the line's job is naming the release that grounds the sighted version.
    pub state: String,
    /// The vendor version actually running.
    pub vendor_version: String,
    /// The pin this build was grounded against, so the line can say both halves.
    pub tested: String,
    /// Distinct kinds of unrecognized input the drift ledger holds for this vendor — the number
    /// the phone prints as "N kinds of message". Zero is the good news and still worth a line.
    pub gaps: u32,
    /// The released Ciao version that covers the running vendor, once the meta manifest says so
    /// (Spec 017 Phase 4). Absent until then; presence turns the promise into an instruction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl DriftNote {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        if !matches!(self.state.as_str(), "ahead" | "carried" | "unsupported") {
            return Err(AgentProtocolError::InvalidValue);
        }
        // An unsupported note exists only to name its fix; without one it would restate the
        // compatibility banner as a second element saying less.
        if self.state == "unsupported" && self.fix.is_none() {
            return Err(AgentProtocolError::InvalidValue);
        }
        valid_token(&self.vendor_version)?;
        valid_token(&self.tested)?;
        if self.gaps > 4096 {
            return Err(AgentProtocolError::InvalidValue);
        }
        if let Some(fix) = &self.fix {
            valid_token(fix)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAdapterMetadata {
    pub family: String,
    pub version: String,
    pub compatibility: String,
}

impl AgentAdapterMetadata {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_token(&self.family)?;
        valid_token(&self.version)?;
        valid_token(&self.compatibility)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionSnapshot {
    pub v: u8,
    pub session_id: String,
    pub snapshot_epoch: u64,
    pub revision: u64,
    pub process_generation: u64,
    pub adapter: AgentAdapterMetadata,
    pub topology: String,
    pub presence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_reason: Option<String>,
    pub control_owner: String,
    pub observation: Observation,
    pub turn: TurnState,
    /// The permission mode the session is running under, where the adapter reports one.
    /// Absent means Ciao does not know — an adapter that never says, or a host older than the
    /// field — which the client must render as unknown rather than as `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    /// The model answering this conversation, where the adapter has reported one. Absent means
    /// Ciao does not know yet — the same honest gap as `permission_mode`, and for a stronger
    /// reason: a managed session has no model until its first turn names one, so anything shown
    /// before that would be a guess. The client renders absent as the vendor's default, never as
    /// a specific model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The reasoning effort in force, reported only once it is actually known. The vendor
    /// silently downgrades an effort the active model cannot do, so an unreported value is left
    /// unreported rather than echoed back as if it had taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// The models this session can actually switch to, as the host read them from the running
    /// adapter. Absent from an adapter that publishes no catalogue, which is what every adapter
    /// did before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models: Option<Vec<AgentModelOption>>,
    /// Present only while the session's vendor runs ahead of this build's grounding
    /// (Spec 017 §4.5). Absent from grounded sessions and from older hosts alike.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift: Option<DriftNote>,
    pub capabilities: AgentCapabilities,
    pub pending_interactions: Vec<PendingInteraction>,
    pub timeline_window: TimelineWindow,
    pub terminal_fallback: TerminalFallback,
    pub latest_command_receipts: Vec<CommandReceipt>,
}

impl AgentSessionSnapshot {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        require_version(self.v)?;
        valid_opaque_id(&self.session_id)?;
        if self.snapshot_epoch == 0 || self.revision == 0 || self.process_generation == 0 {
            return Err(AgentProtocolError::InvalidValue);
        }
        self.adapter.validate()?;
        valid_token(&self.topology)?;
        valid_token(&self.presence)?;
        valid_token(&self.control_owner)?;
        self.observation.validate()?;
        self.turn.validate()?;
        if let Some(mode) = &self.permission_mode
            && !valid_permission_mode(mode)
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        if let Some(model) = &self.model {
            valid_model_id(model)?;
        }
        if let Some(effort) = &self.effort {
            valid_token(effort)?;
        }
        if let Some(models) = &self.models {
            validate_model_catalogue(models)?;
        }
        if let Some(drift) = &self.drift {
            drift.validate()?;
        }
        self.capabilities.validate()?;
        if self.pending_interactions.len() > MAX_PENDING_INTERACTIONS
            || self.latest_command_receipts.len() > MAX_COMMAND_RECEIPTS
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        for interaction in &self.pending_interactions {
            interaction.validate()?;
        }
        for receipt in &self.latest_command_receipts {
            receipt.validate()?;
            if receipt.session_id != self.session_id
                || receipt.process_generation != self.process_generation
                || receipt.snapshot_epoch != self.snapshot_epoch
            {
                return Err(AgentProtocolError::InvalidValue);
            }
        }
        self.timeline_window.validate()?;
        self.terminal_fallback.validate()?;
        // Timeline coverage no longer vetoes a turn: an adapter reporting its own run is
        // first-party fact, while coverage describes how much of the conversation Ciao can see.
        if self.capabilities.terminal_continuity != self.terminal_fallback.continuity
            || (self
                .pending_interactions
                .iter()
                .any(PendingInteraction::is_unresolved_blocking)
                && !matches!(self.turn, TurnState::AwaitingInteraction { .. }))
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        validate_topology_presence(
            &self.topology,
            &self.presence,
            self.stored_reason.as_deref(),
            &self.turn,
            &self.capabilities,
        )?;
        if self.presence == "stored" && !self.pending_interactions.is_empty() {
            return Err(AgentProtocolError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentDeltaChange {
    UpsertEntry {
        entry: TimelineEntry,
    },
    Observation {
        observation: Observation,
    },
    Turn {
        turn: TurnState,
    },
    Capabilities {
        capabilities: AgentCapabilities,
    },
    PermissionMode {
        permission_mode: String,
    },
    Model {
        model: String,
    },
    Effort {
        effort: String,
    },
    /// The whole catalogue at once. Replacing rather than merging is the point: a menu is only
    /// ever right as a set, and a per-row update would let a stale row outlive the list it
    /// belonged to.
    ModelCatalogue {
        models: Vec<AgentModelOption>,
    },
    TerminalFallback {
        terminal_fallback: TerminalFallback,
    },
    UpsertInteraction {
        interaction: PendingInteraction,
    },
    RemoveInteraction {
        interaction_id: String,
        resolution: String,
    },
    CommandReceipt {
        receipt: CommandReceipt,
    },
    #[serde(other)]
    Unknown,
}

impl AgentDeltaChange {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        match self {
            Self::UpsertEntry { entry } => entry.validate(),
            Self::Observation { observation } => observation.validate(),
            Self::Turn { turn } => turn.validate(),
            Self::Capabilities { capabilities } => capabilities.validate(),
            Self::PermissionMode { permission_mode } => {
                if valid_permission_mode(permission_mode) {
                    Ok(())
                } else {
                    Err(AgentProtocolError::InvalidValue)
                }
            }
            Self::Model { model } => valid_model_id(model),
            Self::Effort { effort } => valid_token(effort),
            Self::ModelCatalogue { models } => validate_model_catalogue(models),
            Self::TerminalFallback { terminal_fallback } => terminal_fallback.validate(),
            Self::UpsertInteraction { interaction } => interaction.validate(),
            Self::RemoveInteraction {
                interaction_id,
                resolution,
            } => {
                valid_opaque_id(interaction_id)?;
                valid_token(resolution)
            }
            Self::CommandReceipt { receipt } => receipt.validate(),
            Self::Unknown => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionDelta {
    pub v: u8,
    pub session_id: String,
    pub snapshot_epoch: u64,
    pub process_generation: u64,
    pub base_revision: u64,
    pub revision: u64,
    pub changes: Vec<AgentDeltaChange>,
}

impl AgentSessionDelta {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        require_version(self.v)?;
        valid_opaque_id(&self.session_id)?;
        if self.snapshot_epoch == 0
            || self.process_generation == 0
            || self.base_revision == 0
            || self.revision <= self.base_revision
            || self.changes.is_empty()
            || self.changes.len() > 64
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        for change in &self.changes {
            change.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReduceOutcome {
    Applied,
    Duplicate,
    Stale,
    ResyncRequired(&'static str),
}

/// Canonical reducer used by the host and mirrored in Swift. Continuity changes are applied before
/// all other changes so mutation controls disappear in the same frame as a route downgrade.
pub fn apply_delta(
    snapshot: &mut AgentSessionSnapshot,
    delta: &AgentSessionDelta,
) -> Result<ReduceOutcome, AgentProtocolError> {
    delta.validate()?;
    if delta.session_id != snapshot.session_id
        || delta.snapshot_epoch != snapshot.snapshot_epoch
        || delta.process_generation != snapshot.process_generation
    {
        return Ok(ReduceOutcome::ResyncRequired("identity_fence"));
    }
    if delta.revision <= snapshot.revision {
        return Ok(if delta.revision == snapshot.revision {
            ReduceOutcome::Duplicate
        } else {
            ReduceOutcome::Stale
        });
    }
    if delta.base_revision != snapshot.revision || delta.revision != snapshot.revision + 1 {
        return Ok(ReduceOutcome::ResyncRequired("revision_gap"));
    }

    // Route/capability proof is safety-critical and is committed before presentation content.
    for change in &delta.changes {
        match change {
            AgentDeltaChange::TerminalFallback { terminal_fallback } => {
                snapshot.terminal_fallback = terminal_fallback.clone();
                snapshot.capabilities.terminal_continuity = terminal_fallback.continuity.clone();
            }
            AgentDeltaChange::Capabilities { capabilities } => {
                snapshot.capabilities = capabilities.clone();
            }
            _ => {}
        }
    }

    for change in &delta.changes {
        match change {
            AgentDeltaChange::UpsertEntry { entry } => upsert_entry(snapshot, entry.clone()),
            AgentDeltaChange::Observation { observation } => {
                snapshot.observation = observation.clone();
            }
            AgentDeltaChange::Turn { turn } => snapshot.turn = turn.clone(),
            AgentDeltaChange::PermissionMode { permission_mode } => {
                snapshot.permission_mode = Some(permission_mode.clone());
            }
            AgentDeltaChange::Model { model } => snapshot.model = Some(model.clone()),
            AgentDeltaChange::Effort { effort } => snapshot.effort = Some(effort.clone()),
            AgentDeltaChange::ModelCatalogue { models } => {
                snapshot.models = Some(models.clone());
            }
            AgentDeltaChange::UpsertInteraction { interaction } => {
                upsert_interaction(snapshot, interaction.clone())?;
            }
            AgentDeltaChange::RemoveInteraction {
                interaction_id,
                resolution: _,
            } => snapshot
                .pending_interactions
                .retain(|item| item.interaction_id != *interaction_id),
            AgentDeltaChange::CommandReceipt { receipt } => {
                upsert_receipt(snapshot, receipt.clone())?;
            }
            AgentDeltaChange::Unknown => {
                snapshot.turn = TurnState::Unknown {
                    reason_code: "unsupported_delta".into(),
                };
            }
            AgentDeltaChange::Capabilities { .. } | AgentDeltaChange::TerminalFallback { .. } => {}
        }
    }
    snapshot.revision = delta.revision;
    enforce_reducer_invariants(snapshot)?;
    Ok(ReduceOutcome::Applied)
}

fn upsert_entry(snapshot: &mut AgentSessionSnapshot, entry: TimelineEntry) {
    if let Some(existing) = snapshot
        .timeline_window
        .entries
        .iter_mut()
        .find(|candidate| candidate.entry_id == entry.entry_id)
    {
        if entry.entry_revision > existing.entry_revision {
            *existing = entry;
        }
    } else {
        snapshot.timeline_window.entries.push(entry);
        snapshot
            .timeline_window
            .entries
            .sort_by_key(|candidate| candidate.sequence);
        if snapshot.timeline_window.entries.len() > MAX_TIMELINE_ENTRIES_IN_SNAPSHOT {
            snapshot.timeline_window.entries.remove(0);
            snapshot.timeline_window.has_older = true;
            snapshot.timeline_window.truncated = true;
        }
    }
    snapshot.timeline_window.oldest_sequence = snapshot
        .timeline_window
        .entries
        .first()
        .map(|entry| entry.sequence);
    snapshot.timeline_window.newest_sequence = snapshot
        .timeline_window
        .entries
        .last()
        .map(|entry| entry.sequence);
}

fn upsert_interaction(
    snapshot: &mut AgentSessionSnapshot,
    interaction: PendingInteraction,
) -> Result<(), AgentProtocolError> {
    if let Some(existing) = snapshot
        .pending_interactions
        .iter_mut()
        .find(|candidate| candidate.interaction_id == interaction.interaction_id)
    {
        if interaction.interaction_revision > existing.interaction_revision {
            *existing = interaction;
        }
    } else {
        if snapshot.pending_interactions.len() >= MAX_PENDING_INTERACTIONS {
            return Err(AgentProtocolError::InvalidValue);
        }
        snapshot.pending_interactions.push(interaction);
    }
    Ok(())
}

fn upsert_receipt(
    snapshot: &mut AgentSessionSnapshot,
    receipt: CommandReceipt,
) -> Result<(), AgentProtocolError> {
    if receipt.session_id != snapshot.session_id
        || receipt.snapshot_epoch != snapshot.snapshot_epoch
        || receipt.process_generation != snapshot.process_generation
    {
        return Ok(());
    }
    if let Some(existing) = snapshot
        .latest_command_receipts
        .iter_mut()
        .find(|candidate| candidate.command_id == receipt.command_id)
    {
        // Ambiguous delivery cannot become applied without explicit adapter evidence.
        if existing.state == "outcome_unknown"
            && receipt.state == "applied"
            && receipt.application_evidence.is_none()
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        if receipt.updated_at >= existing.updated_at {
            *existing = receipt;
        }
    } else {
        snapshot.latest_command_receipts.push(receipt);
        if snapshot.latest_command_receipts.len() > MAX_COMMAND_RECEIPTS {
            snapshot.latest_command_receipts.remove(0);
        }
    }
    Ok(())
}

pub fn enforce_reducer_invariants(
    snapshot: &mut AgentSessionSnapshot,
) -> Result<(), AgentProtocolError> {
    if snapshot
        .pending_interactions
        .iter()
        .any(PendingInteraction::is_unresolved_blocking)
    {
        snapshot.turn = TurnState::AwaitingInteraction { run_id: None };
    }
    if snapshot.capabilities.terminal_continuity != snapshot.terminal_fallback.continuity {
        snapshot.capabilities.terminal_continuity = snapshot.terminal_fallback.continuity.clone();
    }
    // No delta may fabricate a terminal route onto a managed session.
    if snapshot.topology == "managed" && snapshot.terminal_fallback.continuity != "unavailable" {
        return Err(AgentProtocolError::InvalidValue);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InteractionAnswer {
    Choices {
        choice_ids: Vec<String>,
    },
    Questions {
        answers: Vec<QuestionAnswer>,
    },
    FreeText {
        text: String,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionAnswer {
    pub question_id: String,
    #[serde(default)]
    pub choice_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentCommandKind {
    Prompt {
        text: String,
    },
    Steer {
        text: String,
    },
    FollowUp {
        text: String,
    },
    Interrupt,
    InteractionResponse {
        interaction_id: String,
        interaction_revision: u64,
        answer: InteractionAnswer,
    },
    SetPermissionMode {
        mode: String,
    },
    SetModel {
        model: String,
    },
    SetEffort {
        effort: String,
    },
    #[serde(other)]
    Unknown,
}

impl AgentCommandKind {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        match self {
            Self::Prompt { text } | Self::Steer { text } | Self::FollowUp { text } => {
                if text.is_empty() || text.len() > MAX_PROMPT_BYTES {
                    return Err(AgentProtocolError::InvalidValue);
                }
            }
            Self::Interrupt => {}
            Self::InteractionResponse {
                interaction_id,
                interaction_revision,
                answer,
            } => {
                valid_opaque_id(interaction_id)?;
                if *interaction_revision == 0 {
                    return Err(AgentProtocolError::InvalidValue);
                }
                validate_answer(answer)?;
            }
            // Checked against the union rather than merely tokenised: this value is handed
            // straight to a worker, and an unrecognised one must be refused here rather than
            // discovered by the vendor.
            Self::SetPermissionMode { mode } => {
                if !valid_permission_mode(mode) {
                    return Err(AgentProtocolError::InvalidValue);
                }
            }
            // Grammar and bounds only — see [`valid_model_id`] for why the closed check lives
            // with the adapter and worker instead of here.
            Self::SetModel { model } => valid_model_id(model)?,
            Self::SetEffort { effort } => valid_token(effort)?,
            Self::Unknown => return Err(AgentProtocolError::InvalidValue),
        }
        Ok(())
    }
}

fn validate_answer(answer: &InteractionAnswer) -> Result<(), AgentProtocolError> {
    match answer {
        InteractionAnswer::Choices { choice_ids } => {
            if choice_ids.is_empty() || choice_ids.len() > MAX_OPTIONS_PER_QUESTION {
                return Err(AgentProtocolError::InvalidValue);
            }
            for choice in choice_ids {
                valid_opaque_id(choice)?;
            }
        }
        InteractionAnswer::Questions { answers } => {
            if answers.is_empty() || answers.len() > MAX_QUESTIONS {
                return Err(AgentProtocolError::InvalidValue);
            }
            for answer in answers {
                valid_opaque_id(&answer.question_id)?;
                if answer.choice_ids.len() > MAX_OPTIONS_PER_QUESTION
                    || answer
                        .text
                        .as_ref()
                        .is_some_and(|text| text.len() > MAX_PROMPT_BYTES)
                {
                    return Err(AgentProtocolError::InvalidValue);
                }
                for choice in &answer.choice_ids {
                    valid_opaque_id(choice)?;
                }
            }
        }
        InteractionAnswer::FreeText { text } => {
            if text.len() > MAX_PROMPT_BYTES {
                return Err(AgentProtocolError::InvalidValue);
            }
        }
        InteractionAnswer::Unknown => return Err(AgentProtocolError::InvalidValue),
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCommand {
    pub v: u8,
    pub command_id: String,
    pub session_id: String,
    pub snapshot_epoch: u64,
    pub expected_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u64>,
    pub kind: AgentCommandKind,
}

impl AgentCommand {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        require_version(self.v)?;
        valid_opaque_id(&self.command_id)?;
        valid_opaque_id(&self.session_id)?;
        if self.snapshot_epoch == 0 || self.expected_generation == 0 {
            return Err(AgentProtocolError::InvalidValue);
        }
        self.kind.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStreamOpen {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub client_instance_id: String,
    pub operation: String,
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_limit: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_command_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<u64>,
}

impl AgentStreamOpen {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        require_version(self.v)?;
        if self.message_type != "agent_stream_open" {
            return Err(AgentProtocolError::UnexpectedMessage);
        }
        valid_opaque_id(&self.client_instance_id)?;
        valid_token(&self.operation)?;
        if self.capabilities.len() > 16
            || !self
                .capabilities
                .iter()
                .any(|capability| capability == CAPABILITY_AGENT_SESSION_V1)
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        for capability in &self.capabilities {
            valid_token(capability)?;
        }
        // (session_id, before_sequence, page_limit, workspace_id, lifecycle_command_id,
        //  expected_generation) — exactly the parameters each operation requires, nothing else.
        let shape = (
            self.session_id.is_some(),
            self.before_sequence.is_some(),
            self.page_limit.is_some(),
            self.workspace_id.is_some(),
            self.lifecycle_command_id.is_some(),
            self.expected_generation.is_some(),
        );
        let valid_shape = match self.operation.as_str() {
            "agent.sessions.list" | "agent.workspaces.list" => {
                shape == (false, false, false, false, false, false)
            }
            "agent.session.snapshot" | "agent.session.subscribe" | "agent.command.submit" => {
                shape == (true, false, false, false, false, false)
            }
            "agent.timeline.page" => {
                shape == (true, true, true, false, false, false)
                    && !self.page_limit.is_none_or(|limit| {
                        limit == 0 || usize::from(limit) > MAX_TIMELINE_PAGE_ENTRIES
                    })
            }
            "agent.managed.start" => shape == (false, false, false, true, true, false),
            "agent.managed.stop" => shape == (true, false, false, false, true, true),
            // Promote takes the same parameters as resume: which session, and the command to
            // correlate it by. Omitting it here rejected every takeover from a phone as a
            // malformed handshake, while the CLI's IPC route — which never sees this — worked.
            // Release is the same shape again, and is listed here rather than later for the
            // same reason: a lifecycle verb that exists only over IPC is not a verb a phone
            // can use.
            // Forget is the same shape again, and joins them for the third time for the reason
            // above: the host has had `managed_forget` since the CLI gained it, so a phone could
            // accumulate stored rows it had no verb to clear and the only cleanup was walking to
            // the machine.
            "agent.managed.resume"
            | "agent.managed.promote"
            | "agent.managed.release"
            | "agent.managed.forget" => shape == (true, false, false, false, true, false),
            // Pick-up takes promote's parameters for promote's reason: which conversation,
            // and the command to correlate the outcome by (Spec 013 §7).
            "agent.adopted.pickup" => shape == (true, false, false, false, true, false),
            _ => return Err(AgentProtocolError::UnexpectedMessage),
        };
        if !valid_shape {
            return Err(AgentProtocolError::InvalidValue);
        }
        if self.operation.starts_with("agent.managed.")
            && !self
                .capabilities
                .iter()
                .any(|capability| capability == CAPABILITY_AGENT_SESSION_MANAGED_V1)
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        if self.operation.starts_with("agent.adopted.")
            && !self
                .capabilities
                .iter()
                .any(|capability| capability == CAPABILITY_AGENT_SESSION_ADOPTED_V1)
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        if let Some(session_id) = &self.session_id {
            valid_opaque_id(session_id)?;
        }
        if let Some(workspace_id) = &self.workspace_id {
            valid_opaque_id(workspace_id)?;
        }
        if let Some(command_id) = &self.lifecycle_command_id {
            valid_opaque_id(command_id)?;
        }
        if self.expected_generation == Some(0) {
            return Err(AgentProtocolError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLimits {
    pub max_frame_bytes: u32,
    pub max_page_entries: u8,
    pub max_page_bytes: u32,
    pub max_prompt_bytes: u32,
    pub max_outbound_queue_bytes: u32,
}

impl Default for AgentLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: MAX_AGENT_FRAME_BYTES as u32,
            max_page_entries: MAX_TIMELINE_PAGE_ENTRIES as u8,
            max_page_bytes: MAX_TIMELINE_PAGE_BYTES as u32,
            max_prompt_bytes: MAX_PROMPT_BYTES as u32,
            max_outbound_queue_bytes: MAX_AGENT_OUTBOUND_QUEUE_BYTES as u32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStreamAccepted {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub operation: String,
    pub server_epoch: u64,
    pub limits: AgentLimits,
}

/// Sorts newest-first, truncates to the session-count bound, then drops oldest
/// descriptors until one list frame fits the wire bound. Omissions are counted
/// categorically, never silent.
pub fn bounded_session_list(
    mut descriptors: Vec<AgentSessionDescriptor>,
    already_omitted: u32,
) -> AgentSessionList {
    descriptors.sort_by_key(|descriptor| std::cmp::Reverse(descriptor.updated_at));
    let mut omitted =
        already_omitted.saturating_add(descriptors.len().saturating_sub(MAX_AGENT_SESSIONS) as u32);
    descriptors.truncate(MAX_AGENT_SESSIONS);
    while serde_json::to_vec(&AgentServerFrame::SessionList {
        v: AGENT_PROTOCOL_VERSION,
        sessions: descriptors.clone(),
        omitted_sessions: omitted,
    })
    .map_or(usize::MAX, |bytes| bytes.len())
        > MAX_AGENT_FRAME_BYTES
    {
        if descriptors.pop().is_none() {
            break;
        }
        omitted = omitted.saturating_add(1);
    }
    AgentSessionList {
        v: AGENT_PROTOCOL_VERSION,
        message_type: "agent_session_list".into(),
        sessions: descriptors,
        omitted_sessions: omitted,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionList {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub sessions: Vec<AgentSessionDescriptor>,
    pub omitted_sessions: u32,
}

impl AgentSessionList {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        require_version(self.v)?;
        if self.message_type != "agent_session_list" || self.sessions.len() > MAX_AGENT_SESSIONS {
            return Err(AgentProtocolError::InvalidValue);
        }
        for descriptor in &self.sessions {
            descriptor.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelinePage {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub session_id: String,
    pub snapshot_epoch: u64,
    pub process_generation: u64,
    pub entries: Vec<TimelineEntry>,
    pub has_older: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_before_sequence: Option<u64>,
    pub aggregate_bytes: u32,
}

impl TimelinePage {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        require_version(self.v)?;
        if self.message_type != "agent_timeline_page"
            || self.snapshot_epoch == 0
            || self.process_generation == 0
            || self.entries.len() > MAX_TIMELINE_PAGE_ENTRIES
            || usize::try_from(self.aggregate_bytes).unwrap_or(usize::MAX) > MAX_TIMELINE_PAGE_BYTES
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        valid_opaque_id(&self.session_id)?;
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceDescriptor {
    pub workspace_id: String,
    pub display_label: String,
}

impl WorkspaceDescriptor {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_opaque_id(&self.workspace_id)?;
        if self.display_label.is_empty() || self.display_label.len() > MAX_WORKSPACE_LABEL_BYTES {
            return Err(AgentProtocolError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWorkspaceList {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub workspaces: Vec<WorkspaceDescriptor>,
    pub omitted_workspaces: u32,
    /// The host could not see all of home: the scan hit its deadline, or a directory refused to
    /// be read. The list is still usable, it is just not necessarily the whole of what is there —
    /// which the phone has to say, because a short list and a complete list look identical.
    ///
    /// `default` so a fixture or a peer written before this field still deserializes.
    #[serde(default)]
    pub scan_incomplete: bool,
}

impl AgentWorkspaceList {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        require_version(self.v)?;
        if self.message_type != "agent_workspace_list"
            || self.workspaces.len() > MAX_WORKSPACE_LIST_ENTRIES
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        for workspace in &self.workspaces {
            workspace.validate()?;
        }
        Ok(())
    }
}

/// Receipted outcome of a managed lifecycle operation. `state` is `accepted`
/// or `refused`; a refusal always carries a categorical reason code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleOutcome {
    pub v: u8,
    pub command_id: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deduplicated: Option<bool>,
    /// The command that reopens a conversation this outcome just surrendered.
    ///
    /// Carried on the release response rather than left to be read off the refreshed
    /// descriptor, because releasing is precisely when that refresh is least likely to
    /// arrive: the worker it stops takes the connection's traffic with it, and the phone's
    /// follow-up list raced the teardown and lost. The client copied nothing and showed an
    /// error, on the one action whose entire purpose is handing over the command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_command: Option<String>,
}

impl LifecycleOutcome {
    pub fn validate(&self) -> Result<(), AgentProtocolError> {
        require_version(self.v)?;
        valid_opaque_id(&self.command_id)?;
        valid_token(&self.state)?;
        if let Some(session_id) = &self.session_id {
            valid_opaque_id(session_id)?;
        }
        if let Some(reason) = &self.reason_code {
            valid_token(reason)?;
        }
        if let Some(command) = &self.resume_command {
            valid_resume_command(command)?;
        }
        match self.state.as_str() {
            "accepted" if self.reason_code.is_some() => Err(AgentProtocolError::InvalidValue),
            "refused" if self.reason_code.is_none() => Err(AgentProtocolError::InvalidValue),
            // A refusal surrendered nothing, so it has nothing to hand over.
            "refused"
                if self.session_id.is_some()
                    || self.process_generation.is_some()
                    || self.resume_command.is_some() =>
            {
                Err(AgentProtocolError::InvalidValue)
            }
            "accepted" | "refused" => Ok(()),
            _ => Err(AgentProtocolError::InvalidValue),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentClientFrame {
    CommandSubmit {
        command: AgentCommand,
    },
    Close,
    #[serde(other)]
    Unknown,
}

/// `skip_serializing_if` for a flag whose absence means false.
fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentServerFrame {
    StreamAccepted {
        v: u8,
        operation: String,
        server_epoch: u64,
        limits: AgentLimits,
    },
    SessionList {
        v: u8,
        sessions: Vec<AgentSessionDescriptor>,
        omitted_sessions: u32,
    },
    SessionSnapshot {
        v: u8,
        snapshot: Box<AgentSessionSnapshot>,
    },
    TimelinePage {
        v: u8,
        page: TimelinePage,
    },
    TimelinePageStart {
        v: u8,
        page_id: String,
        session_id: String,
        snapshot_epoch: u64,
        process_generation: u64,
        total_entries: u8,
        aggregate_bytes: u32,
        has_older: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        next_before_sequence: Option<u64>,
    },
    TimelinePageEntry {
        v: u8,
        page_id: String,
        entry: TimelineEntry,
    },
    TimelinePageEnd {
        v: u8,
        page_id: String,
    },
    SessionDelta {
        v: u8,
        delta: AgentSessionDelta,
    },
    CommandReceipt {
        v: u8,
        receipt: CommandReceipt,
    },
    ResyncRequired {
        v: u8,
        session_id: String,
        reason_code: String,
    },
    WorkspaceList {
        v: u8,
        workspaces: Vec<WorkspaceDescriptor>,
        omitted_workspaces: u32,
        /// See `AgentWorkspaceList::scan_incomplete`.
        ///
        /// Omitted when false, which is the only reason an app built before this field can still
        /// read this frame: iOS validates the key set of every frame it decodes and rejects one
        /// carrying a key it does not know. Hosts update on their own schedule and phones update
        /// through TestFlight, so "always send it" would have broken the New agent sheet on every
        /// phone that had not caught up yet. The cost is that an old app facing an incomplete
        /// scan — the rare case — sees the frame refused rather than a short list, and says the
        /// host offers no managed sessions. Wrong, but it stops, which is more than the hang it
        /// replaces.
        #[serde(default, skip_serializing_if = "is_false")]
        scan_incomplete: bool,
    },
    LifecycleOutcome {
        v: u8,
        outcome: LifecycleOutcome,
    },
    Error {
        v: u8,
        code: String,
    },
    #[serde(other)]
    Unknown,
}

pub fn encode_agent_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, AgentProtocolError> {
    let body = serde_json::to_vec(value).map_err(|_| AgentProtocolError::MalformedJson)?;
    if body.is_empty() {
        return Err(AgentProtocolError::ZeroLength);
    }
    if body.len() > MAX_AGENT_FRAME_BYTES {
        return Err(AgentProtocolError::FrameTooLarge);
    }
    let length = u32::try_from(body.len()).map_err(|_| AgentProtocolError::FrameTooLarge)?;
    let mut encoded = Vec::with_capacity(4 + body.len());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

pub fn decode_agent_body<T: for<'de> Deserialize<'de>>(
    body: &[u8],
) -> Result<T, AgentProtocolError> {
    if body.is_empty() {
        return Err(AgentProtocolError::ZeroLength);
    }
    if body.len() > MAX_AGENT_FRAME_BYTES {
        return Err(AgentProtocolError::FrameTooLarge);
    }
    serde_json::from_slice(body).map_err(|_| AgentProtocolError::MalformedJson)
}

/// Frame reader that is safe to drop mid-read, unlike `read_agent_frame`, whose `read_exact`
/// loses already-consumed bytes when a `tokio::select!` picks another branch. The adapter bridge
/// and the phone's subscription loop both race a read against channels that fire mid-frame, so a
/// dropped partial header desynced the stream — the same defect the terminal bridge had. Bytes
/// are consumed only by single completed `read` calls, and buffer state outlives the future.
#[derive(Debug)]
pub struct AgentFrameReader {
    buffered: Vec<u8>,
    chunk: Vec<u8>,
}

impl Default for AgentFrameReader {
    fn default() -> Self {
        Self {
            buffered: Vec::new(),
            chunk: vec![0_u8; 8 * 1024],
        }
    }
}

impl AgentFrameReader {
    /// Cancellation-safe: dropping the returned future never loses stream position.
    pub async fn next<R>(&mut self, reader: &mut R) -> Result<Vec<u8>, AgentProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            if let Some(body) = self.take_frame()? {
                return Ok(body);
            }
            let count = match reader.read(&mut self.chunk).await {
                Ok(0) => return Err(AgentProtocolError::Truncated),
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(AgentProtocolError::Truncated);
                }
                Err(error) => return Err(AgentProtocolError::Io(error)),
            };
            self.buffered.extend_from_slice(&self.chunk[..count]);
        }
    }

    fn take_frame(&mut self) -> Result<Option<Vec<u8>>, AgentProtocolError> {
        if self.buffered.len() < 4 {
            return Ok(None);
        }
        let length = u32::from_be_bytes(
            self.buffered[..4]
                .try_into()
                .expect("four-byte frame length"),
        ) as usize;
        if length == 0 {
            return Err(AgentProtocolError::ZeroLength);
        }
        if length > MAX_AGENT_FRAME_BYTES {
            return Err(AgentProtocolError::FrameTooLarge);
        }
        if self.buffered.len() < 4 + length {
            return Ok(None);
        }
        let body = self.buffered[4..4 + length].to_vec();
        self.buffered.drain(..4 + length);
        Ok(Some(body))
    }
}

pub async fn read_agent_frame<R>(reader: &mut R) -> Result<Vec<u8>, AgentProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    read_exact(reader, &mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(AgentProtocolError::ZeroLength);
    }
    if length > MAX_AGENT_FRAME_BYTES {
        return Err(AgentProtocolError::FrameTooLarge);
    }
    let mut body = vec![0_u8; length];
    read_exact(reader, &mut body).await?;
    Ok(body)
}

pub async fn write_agent_frame<W, T>(writer: &mut W, value: &T) -> Result<(), AgentProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    writer.write_all(&encode_agent_frame(value)?).await?;
    Ok(())
}

async fn read_exact<R>(reader: &mut R, buffer: &mut [u8]) -> Result<(), AgentProtocolError>
where
    R: AsyncRead + Unpin,
{
    match reader.read_exact(buffer).await {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(AgentProtocolError::Truncated)
        }
        Err(error) => Err(AgentProtocolError::Io(error)),
    }
}

/// The one place that turns a bridge's turn frame into a [`TurnState`].
///
/// Every integration reports the same two edges in the same words, so no adapter gets to invent
/// its own vocabulary for "working" and the phone never learns which agent it is talking to. Only
/// what a bridge can actually prove is accepted: a running turn must name the run it is running,
/// and a state Ciao never defined is refused rather than shown as unexplained activity.
pub fn turn_from_bridge_frame(
    state: &str,
    run_id: Option<String>,
    activity: Option<String>,
) -> Result<TurnState, AgentProtocolError> {
    let turn = match state {
        "running" => TurnState::Running {
            run_id: run_id.ok_or(AgentProtocolError::InvalidValue)?,
            activity: activity.ok_or(AgentProtocolError::InvalidValue)?,
        },
        "completed" => TurnState::Completed { run_id },
        _ => return Err(AgentProtocolError::InvalidValue),
    };
    turn.validate()?;
    Ok(turn)
}

pub fn valid_token(value: &str) -> Result<(), AgentProtocolError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_TOKEN_BYTES
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AgentProtocolError::InvalidValue);
    }
    Ok(())
}

pub fn valid_opaque_id(value: &str) -> Result<(), AgentProtocolError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_OPAQUE_ID_BYTES
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AgentProtocolError::InvalidValue);
    }
    Ok(())
}

fn require_version(version: u8) -> Result<(), AgentProtocolError> {
    if version == AGENT_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(AgentProtocolError::UnsupportedVersion)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::Value;

    use super::*;

    /// One loader for every phase's fixture corpus. The attached/managed/adopted test families
    /// below stay separate on purpose: their assertions document genuinely different topology
    /// surfaces (only managed has workspaces and lifecycle verbs; only adopted has a write
    /// surface), and a shared table would hide exactly those differences.
    fn load_fixture(relative: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../protocol/fixtures")
            .join(relative);
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap()
    }

    fn fixture() -> Value {
        load_fixture("phase4/agent-session-v1.json")
    }

    fn hostile_fixture() -> Value {
        load_fixture("phase4/agent-hostile-v1.json")
    }

    fn bounds_fixture() -> Value {
        load_fixture("phase4/agent-bounds-v1.json")
    }

    fn snapshot() -> AgentSessionSnapshot {
        serde_json::from_value(fixture()["snapshot"].clone()).unwrap()
    }

    #[test]
    fn canonical_fixture_validates_without_adapter_types() {
        let value = fixture();
        let list: AgentSessionList = serde_json::from_value(value["list"].clone()).unwrap();
        list.validate().unwrap();
        // The takeover verb is advertised wire state, not a family inference — which is why a
        // family-neutral fixture row can carry it.
        assert_eq!(list.sessions[0].takeover.as_deref(), Some("promote"));
        let snapshot = snapshot();
        snapshot.validate().unwrap();
        let page: TimelinePage = serde_json::from_value(value["page"].clone()).unwrap();
        page.validate().unwrap();
        for interaction in value["interaction_cases"].as_array().unwrap() {
            let interaction: PendingInteraction =
                serde_json::from_value(interaction.clone()).unwrap();
            interaction.validate().unwrap();
        }
        for receipt in value["receipt_cases"].as_array().unwrap() {
            let receipt: CommandReceipt = serde_json::from_value(receipt.clone()).unwrap();
            receipt.validate().unwrap();
        }
    }

    #[tokio::test]
    async fn shared_hostile_fixture_fails_or_downgrades_as_declared() {
        let hostile = hostile_fixture();
        let cases = hostile["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 6);

        let mut zero = &0_u32.to_be_bytes()[..];
        assert!(matches!(
            read_agent_frame(&mut zero).await,
            Err(AgentProtocolError::ZeroLength)
        ));
        let declared = cases[1]["declared_length"].as_u64().unwrap() as u32;
        let mut oversized = &declared.to_be_bytes()[..];
        assert!(matches!(
            read_agent_frame(&mut oversized).await,
            Err(AgentProtocolError::FrameTooLarge)
        ));
        assert!(matches!(
            decode_agent_body::<Value>(&[0xff]),
            Err(AgentProtocolError::MalformedJson)
        ));
        let unknown = serde_json::to_vec(&cases[3]["json"]).unwrap();
        assert!(matches!(
            decode_agent_body::<AgentClientFrame>(&unknown).unwrap(),
            AgentClientFrame::Unknown
        ));

        let base: AgentSessionDelta =
            serde_json::from_value(fixture()["deltas"].as_array().unwrap()[0].clone()).unwrap();
        let mut stale_generation = base.clone();
        stale_generation.process_generation = cases[4]["generation"].as_u64().unwrap();
        let mut state = snapshot();
        assert_eq!(
            apply_delta(&mut state, &stale_generation).unwrap(),
            ReduceOutcome::ResyncRequired("identity_fence")
        );
        let mut stale_epoch = base;
        stale_epoch.snapshot_epoch = cases[5]["epoch"].as_u64().unwrap();
        let mut state = snapshot();
        assert_eq!(
            apply_delta(&mut state, &stale_epoch).unwrap(),
            ReduceOutcome::ResyncRequired("identity_fence")
        );
        assert_eq!(cases[0]["expect"], "zero_length");
        assert_eq!(cases[1]["expect"], "frame_too_large");
        assert_eq!(cases[2]["expect"], "malformed_json");
        assert_eq!(cases[3]["expect"], "unsupported");
    }

    #[test]
    fn reducer_replaces_streams_and_fences_duplicate_reordered_and_gapped_events() {
        let value = fixture();
        let mut state = snapshot();
        let deltas: Vec<AgentSessionDelta> =
            serde_json::from_value(value["deltas"].clone()).unwrap();
        assert_eq!(
            apply_delta(&mut state, &deltas[0]).unwrap(),
            ReduceOutcome::Applied
        );
        let count = state.timeline_window.entries.len();
        assert_eq!(
            apply_delta(&mut state, &deltas[0]).unwrap(),
            ReduceOutcome::Duplicate
        );
        assert_eq!(state.timeline_window.entries.len(), count);
        assert_eq!(
            apply_delta(&mut state, &deltas[2]).unwrap(),
            ReduceOutcome::ResyncRequired("revision_gap")
        );
        assert_eq!(
            apply_delta(&mut state, &deltas[1]).unwrap(),
            ReduceOutcome::Applied
        );
        let entry = state
            .timeline_window
            .entries
            .iter()
            .find(|entry| entry.entry_id == "entry-assistant")
            .unwrap();
        assert_eq!(entry.entry_revision, 3);
        assert_eq!(entry.state, "complete");
    }

    #[test]
    fn reducer_properties_hold_across_order_duplicate_missing_and_concurrent_changes() {
        let value = fixture();
        let deltas: Vec<AgentSessionDelta> =
            serde_json::from_value(value["deltas"].clone()).unwrap();
        let permutations = [
            vec![0, 1],
            vec![0, 0, 1],
            vec![1, 0],
            vec![0],
            vec![0, 2, 1],
        ];
        for order in permutations {
            let mut state = snapshot();
            for index in order {
                let _ = apply_delta(&mut state, &deltas[index]);
                assert!(!state.turn.is_authoritative_working());
                assert_eq!(
                    state.capabilities.terminal_continuity, state.terminal_fallback.continuity,
                    "capability continuity always mirrors the proven route"
                );
                if state
                    .pending_interactions
                    .iter()
                    .any(PendingInteraction::is_unresolved_blocking)
                {
                    assert!(matches!(state.turn, TurnState::AwaitingInteraction { .. }));
                }
            }
        }
    }

    /// Spec 017 §4.5: the drift note is bounded and closed like everything else on this wire,
    /// and absent-by-default so canonical bytes and older apps never see it.
    #[test]
    fn a_drift_note_is_bounded_validated_and_absent_by_default() {
        let note = DriftNote {
            state: "ahead".into(),
            vendor_version: "2.2.0".into(),
            tested: "2.1.222".into(),
            gaps: 2,
            fix: None,
        };
        note.validate().unwrap();
        let bytes = serde_json::to_string(&note).unwrap();
        assert!(
            !bytes.contains("fix"),
            "an absent fix serializes as nothing"
        );

        let mut wrong_state = note.clone();
        wrong_state.state = "confident".into();
        assert!(wrong_state.validate().is_err(), "states are a closed set");
        let mut oversized = note.clone();
        oversized.gaps = 100_000;
        assert!(oversized.validate().is_err(), "gap counts are bounded");
        let mut hostile = note.clone();
        hostile.vendor_version = "2.2.0\nnot a version".into();
        assert!(hostile.validate().is_err(), "versions stay tokens");

        // A serialized note with a field from the future is refused host-side (this struct is
        // Ciao-owned wire), while the note's *absence* from any frame stays valid — which is
        // what lets older hosts and newer apps coexist.
        let widened: Result<DriftNote, _> = serde_json::from_str(
            r#"{"state":"ahead","vendor_version":"2.2.0","tested":"2.1.222","gaps":1,"mood":"good"}"#,
        );
        assert!(widened.is_err());
    }

    #[test]
    fn unknown_unions_never_enable_authority_or_mutation() {
        let value = fixture();
        let mut state = snapshot();
        let delta: AgentSessionDelta =
            serde_json::from_value(value["unknown_delta"].clone()).unwrap();
        assert_eq!(
            apply_delta(&mut state, &delta).unwrap(),
            ReduceOutcome::Applied
        );
        assert!(matches!(state.turn, TurnState::Unknown { .. }));
        assert!(!state.turn.is_authoritative_working());
    }

    #[test]
    fn blocking_interaction_wins_and_plan_content_does_not_create_a_decision() {
        let mut state = snapshot();
        state.turn = TurnState::Running {
            run_id: "run-a".into(),
            activity: "responding".into(),
        };
        state.observation.coverage = "authoritative".into();
        // Plan timeline content alone is presentation and leaves the turn unchanged.
        state.timeline_window.entries.push(TimelineEntry {
            entry_id: "entry-plan".into(),
            entry_revision: 1,
            sequence: 99,
            timestamp: 1,
            state: "complete".into(),
            kind: "plan".into(),
            body: TimelineBody::Text {
                text: "Synthetic plan content.".into(),
            },
            truncation: Truncation {
                truncated: false,
                reason_code: None,
                original_bytes: None,
            },
        });
        enforce_reducer_invariants(&mut state).unwrap();
        assert!(matches!(state.turn, TurnState::Running { .. }));

        let interaction: PendingInteraction =
            serde_json::from_value(fixture()["interaction_cases"].as_array().unwrap()[4].clone())
                .unwrap();
        state.pending_interactions.push(interaction);
        enforce_reducer_invariants(&mut state).unwrap();
        assert!(matches!(state.turn, TurnState::AwaitingInteraction { .. }));
    }

    #[test]
    fn exact_live_loss_removes_continuity_but_keeps_bridge_commands() {
        let value = fixture();
        let mut state = snapshot();
        assert!(state.capabilities.commands.prompt);
        let delta: AgentSessionDelta =
            serde_json::from_value(value["downgrade_delta"].clone()).unwrap();
        assert_eq!(
            apply_delta(&mut state, &delta).unwrap(),
            ReduceOutcome::Applied
        );
        assert_eq!(state.terminal_fallback.continuity, "workspace_only");
        assert_eq!(state.capabilities.terminal_continuity, "workspace_only");
        // Native commands are bridge-gated: losing the exact terminal route must not
        // silently revoke messaging that the authenticated bridge still advertises.
        assert!(state.capabilities.commands.prompt);
    }

    /// The resume command is the third route representation and the only one that outlives the
    /// terminal it was created for. It joins a live route or stands alone, it never appears on
    /// a continuity that promises a pane, and it cannot carry anything a paste would split
    /// into two commands.
    #[test]
    fn a_resume_command_is_a_route_of_its_own_but_never_a_pane() {
        let resumable = |route_id: Option<&str>, resume: Option<&str>| TerminalFallback {
            continuity: "resumable_session".into(),
            route_id: route_id.map(str::to_owned),
            availability_reason: None,
            handback_session: None,
            resume_command: resume.map(str::to_owned),
        };
        // Alone it is the whole route — the released-with-no-terminal case.
        resumable(None, Some("claude --resume abc123"))
            .validate()
            .unwrap();
        // Alongside a live resolver it is the durable second way in.
        resumable(Some("route-1"), Some("codex resume abc123"))
            .validate()
            .unwrap();
        // Neither is still nothing.
        assert!(resumable(None, None).validate().is_err());

        // A pane is an exact claim; a resume command is not, so the two never coexist.
        assert!(
            TerminalFallback {
                continuity: "exact_live".into(),
                route_id: Some("route-1".into()),
                availability_reason: None,
                handback_session: None,
                resume_command: Some("claude --resume abc123".into()),
            }
            .validate()
            .is_err()
        );
        // Nothing available means nothing available.
        assert!(
            TerminalFallback {
                continuity: "unavailable".into(),
                route_id: None,
                availability_reason: None,
                handback_session: None,
                resume_command: Some("claude --resume abc123".into()),
            }
            .validate()
            .is_err()
        );

        // The grammar is a pasteable argv line, not a shell line.
        for hostile in [
            "claude --resume abc; rm -rf /",
            "claude --resume $(whoami)",
            "claude --resume abc\nrm -rf /",
            "claude --resume ../../etc/passwd",
            "claude --resume 'abc'",
            " claude --resume abc",
            "claude --resume abc ",
            "",
        ] {
            assert!(
                valid_resume_command(hostile).is_err(),
                "accepted a command it must refuse: {hostile:?}"
            );
        }
        assert!(valid_resume_command(&format!("claude --resume {}", "a".repeat(200))).is_err());
        assert!(
            valid_resume_command("claude --resume 0d3eea32-fc11-4935-8053-332c43e23ca3").is_ok()
        );
    }

    #[test]
    fn a_later_patch_is_covered_but_a_minor_bump_is_not() {
        for (running, tested, covered) in [
            ("0.81.1", "0.81.1", true),
            // The case that stranded every routine upgrade.
            ("0.86.1", "0.86.0", true),
            ("0.81.9", "0.81.1", true),
            // Older patch: the tested build may need something added after it.
            ("0.81.0", "0.81.1", false),
            // A 0.x minor is breaking by convention — Pi 0.81 to 0.82 is the real case.
            ("0.82.0", "0.81.1", false),
            ("2.2.0", "2.1.220", false),
            ("3.1.220", "2.1.220", false),
            // A prerelease is not a tested release, whatever it sorts next to.
            ("0.81.2-rc1", "0.81.1", false),
            ("0.81", "0.81.1", false),
            ("", "0.81.1", false),
        ] {
            assert_eq!(
                version_within_tested_minor(running, tested),
                covered,
                "{running} against {tested}"
            );
        }
    }

    /// Model ids are vendor-shaped and the token grammar is not: `claude-opus-5[1m]` is a real
    /// id whose brackets `valid_token` rejects. This is the whole reason model ids have a
    /// grammar of their own rather than reusing the token one.
    #[test]
    fn a_model_id_may_carry_brackets_where_a_token_may_not() {
        assert!(valid_token("claude-opus-5[1m]").is_err());
        assert!(valid_model_id("claude-opus-5[1m]").is_ok());
        assert!(valid_model_id("claude-sonnet-5").is_ok());
        assert!(valid_model_id("sonnet").is_ok());
        assert!(valid_model_id(&"x".repeat(MAX_MODEL_ID_BYTES)).is_ok());

        for hostile in [
            "",
            "model with spaces",
            "model/../etc",
            "model\u{0000}",
            "modèle",
            "model\n",
        ] {
            assert!(valid_model_id(hostile).is_err(), "{hostile:?} is not an id");
        }
        assert!(valid_model_id(&"x".repeat(MAX_MODEL_ID_BYTES + 1)).is_err());
    }

    /// Model and effort ride the snapshot, the delta, and the command on the same terms the
    /// permission mode does — absent means unknown, and a value present must be well formed.
    #[test]
    fn model_and_effort_travel_as_optional_reported_state() {
        let mut reported = snapshot();
        // Absent is the honest default: a managed worker has no model until its first turn.
        assert!(reported.model.is_none() && reported.effort.is_none() && reported.models.is_none());
        reported.validate().unwrap();

        reported.model = Some("claude-opus-5[1m]".into());
        reported.effort = Some("xhigh".into());
        reported.models = Some(vec![AgentModelOption {
            value: "claude-opus-5[1m]".into(),
            display_name: "Opus 5 (1M)".into(),
            supports_effort: true,
            supported_effort_levels: vec!["low".into(), "max".into()],
        }]);
        reported.validate().unwrap();

        // A snapshot without the fields still round-trips through a host that has them, which is
        // what lets an older peer stay readable.
        let encoded = serde_json::to_value(&reported).unwrap();
        assert_eq!(encoded["model"], "claude-opus-5[1m]");
        assert_eq!(encoded["models"][0]["display_name"], "Opus 5 (1M)");
        let mut bare = snapshot();
        bare.permission_mode = None;
        let bare_encoded = serde_json::to_value(&bare).unwrap();
        assert!(bare_encoded.get("model").is_none(), "absent stays absent");
        assert!(bare_encoded.get("models").is_none());

        for hostile in [
            Some("model with spaces".to_owned()),
            Some(String::new()),
            Some("x".repeat(MAX_MODEL_ID_BYTES + 1)),
        ] {
            let mut broken = snapshot();
            broken.model = hostile.clone();
            assert!(broken.validate().is_err(), "{hostile:?} is not an id");
        }
        let mut over_long = snapshot();
        over_long.models = Some(
            (0..=MAX_MODEL_CATALOGUE_ENTRIES)
                .map(|index| AgentModelOption {
                    value: format!("model-{index}"),
                    display_name: "M".into(),
                    supports_effort: false,
                    supported_effort_levels: Vec::new(),
                })
                .collect(),
        );
        assert!(over_long.validate().is_err(), "a catalogue is bounded");

        // Deltas carry the same three facts, and applying one moves exactly what it names.
        let catalogue = vec![AgentModelOption {
            value: "claude-sonnet-5".into(),
            display_name: "Sonnet 5".into(),
            supports_effort: false,
            supported_effort_levels: Vec::new(),
        }];
        for change in [
            AgentDeltaChange::Model {
                model: "claude-sonnet-5".into(),
            },
            AgentDeltaChange::Effort {
                effort: "low".into(),
            },
            AgentDeltaChange::ModelCatalogue {
                models: catalogue.clone(),
            },
        ] {
            change.validate().unwrap();
        }
        for hostile in [
            AgentDeltaChange::Model {
                model: "a/b".into(),
            },
            AgentDeltaChange::Effort {
                effort: "not a level".into(),
            },
            AgentDeltaChange::ModelCatalogue {
                models: vec![AgentModelOption {
                    value: "m".into(),
                    display_name: "N".repeat(MAX_MODEL_DISPLAY_NAME_BYTES + 1),
                    supports_effort: false,
                    supported_effort_levels: Vec::new(),
                }],
            },
        ] {
            assert!(hostile.validate().is_err());
        }

        let mut target = snapshot();
        let delta = AgentSessionDelta {
            v: 1,
            session_id: target.session_id.clone(),
            snapshot_epoch: target.snapshot_epoch,
            process_generation: target.process_generation,
            base_revision: target.revision,
            revision: target.revision + 1,
            changes: vec![
                AgentDeltaChange::Model {
                    model: "claude-sonnet-5".into(),
                },
                AgentDeltaChange::Effort {
                    effort: "low".into(),
                },
                AgentDeltaChange::ModelCatalogue { models: catalogue },
            ],
        };
        apply_delta(&mut target, &delta).unwrap();
        assert_eq!(target.model.as_deref(), Some("claude-sonnet-5"));
        assert_eq!(target.effort.as_deref(), Some("low"));
        assert_eq!(target.models.unwrap().len(), 1);
    }

    /// The capability gate is what keeps an adapter from being asked for something it cannot do,
    /// and an absent capability must read as "not offered" rather than break the decode.
    #[test]
    fn model_and_effort_commands_are_capability_gated_and_default_off() {
        let legacy: CommandCapabilities = serde_json::from_value(serde_json::json!({
            "prompt": true, "steer": false, "follow_up": false, "interrupt": true
        }))
        .unwrap();
        assert!(!legacy.model && !legacy.effort && !legacy.permission_mode);

        let model = AgentCommandKind::SetModel {
            model: "claude-opus-5[1m]".into(),
        };
        let effort = AgentCommandKind::SetEffort {
            effort: "high".into(),
        };
        model.validate().unwrap();
        effort.validate().unwrap();
        assert!(!CommandCapabilities::none().permits(&model));
        assert!(!CommandCapabilities::none().permits(&effort));

        let offered = CommandCapabilities {
            prompt: true,
            steer: false,
            follow_up: false,
            interrupt: true,
            permission_mode: true,
            model: true,
            effort: true,
        };
        assert!(offered.permits(&model) && offered.permits(&effort));
        // Separately gated: a host offering one is not offering the other.
        let model_only = CommandCapabilities {
            effort: false,
            ..offered.clone()
        };
        assert!(model_only.permits(&model) && !model_only.permits(&effort));

        // Grammar and bounds are refused at the protocol layer; the vendor's own union is the
        // adapter's business, so a plausible-but-unknown level passes here on purpose.
        assert!(
            AgentCommandKind::SetEffort {
                effort: "ludicrous".into()
            }
            .validate()
            .is_ok(),
            "the vendor union is the adapter's to enforce, not this layer's"
        );
        for hostile in [
            AgentCommandKind::SetModel {
                model: "a b".into(),
            },
            AgentCommandKind::SetModel {
                model: String::new(),
            },
            AgentCommandKind::SetEffort {
                effort: "with spaces".into(),
            },
        ] {
            assert!(hostile.validate().is_err());
        }
    }

    #[test]
    fn command_and_every_phase_bound_are_exact() {
        let bounds = bounds_fixture();
        for (name, actual) in [
            ("agent_frame_bytes", MAX_AGENT_FRAME_BYTES),
            ("session_list_count", MAX_AGENT_SESSIONS),
            ("session_list_bytes", MAX_AGENT_LIST_BYTES),
            ("timeline_page_entries", MAX_TIMELINE_PAGE_ENTRIES),
            ("timeline_page_bytes", MAX_TIMELINE_PAGE_BYTES),
            ("live_text_delta_bytes", MAX_LIVE_TEXT_DELTA_BYTES),
            ("prompt_bytes", MAX_PROMPT_BYTES),
            ("pending_interactions", MAX_PENDING_INTERACTIONS),
            ("questions", MAX_QUESTIONS),
            ("options_per_question", MAX_OPTIONS_PER_QUESTION),
            ("tool_input_preview_bytes", MAX_TOOL_INPUT_PREVIEW_BYTES),
            ("tool_result_preview_bytes", MAX_TOOL_RESULT_PREVIEW_BYTES),
            ("outbound_queue_bytes", MAX_AGENT_OUTBOUND_QUEUE_BYTES),
            ("command_receipts", MAX_COMMAND_RECEIPTS),
            ("adapter_token_bytes", MAX_TOKEN_BYTES),
            ("route_id_bytes", MAX_OPAQUE_ID_BYTES),
            ("recent_prompt_bytes", MAX_RECENT_PROMPT_BYTES),
            ("model_catalogue_entries", MAX_MODEL_CATALOGUE_ENTRIES),
            ("model_id_bytes", MAX_MODEL_ID_BYTES),
            ("model_display_name_bytes", MAX_MODEL_DISPLAY_NAME_BYTES),
            ("effort_levels_per_model", MAX_EFFORT_LEVELS_PER_MODEL),
        ] {
            assert_eq!(bounds[name].as_u64().unwrap(), actual as u64, "{name}");
        }
        let base = AgentCommand {
            v: 1,
            command_id: "command-a".into(),
            session_id: "session-a".into(),
            snapshot_epoch: 1,
            expected_generation: 1,
            expected_revision: Some(1),
            kind: AgentCommandKind::Prompt {
                text: "x".repeat(MAX_PROMPT_BYTES),
            },
        };
        base.validate().unwrap();
        let mut over = base.clone();
        over.kind = AgentCommandKind::Prompt {
            text: "x".repeat(MAX_PROMPT_BYTES + 1),
        };
        assert!(over.validate().is_err());
        assert!(valid_token(&"x".repeat(MAX_TOKEN_BYTES)).is_ok());
        assert!(valid_token(&"x".repeat(MAX_TOKEN_BYTES + 1)).is_err());
        assert!(valid_opaque_id(&"x".repeat(MAX_OPAQUE_ID_BYTES)).is_ok());
        assert!(valid_opaque_id(&"x".repeat(MAX_OPAQUE_ID_BYTES + 1)).is_err());
    }

    #[tokio::test]
    async fn framing_fragments_coalesces_and_rejects_zero_truncated_oversized_and_malformed() {
        let frame = AgentServerFrame::Error {
            v: 1,
            code: "categorical_error".into(),
        };
        let encoded = encode_agent_frame(&frame).unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(encoded.len() * 2);
        writer.write_all(&encoded[..2]).await.unwrap();
        writer.write_all(&encoded[2..]).await.unwrap();
        let body = read_agent_frame(&mut reader).await.unwrap();
        let decoded: AgentServerFrame = decode_agent_body(&body).unwrap();
        assert_eq!(decoded, frame);

        let mut zero = &0_u32.to_be_bytes()[..];
        assert!(matches!(
            read_agent_frame(&mut zero).await,
            Err(AgentProtocolError::ZeroLength)
        ));
        let mut oversized = &((MAX_AGENT_FRAME_BYTES as u32) + 1).to_be_bytes()[..];
        assert!(matches!(
            read_agent_frame(&mut oversized).await,
            Err(AgentProtocolError::FrameTooLarge)
        ));
        let mut truncated = &[0_u8, 0, 0, 4, b'{'][..];
        assert!(matches!(
            read_agent_frame(&mut truncated).await,
            Err(AgentProtocolError::Truncated)
        ));
        assert!(matches!(
            decode_agent_body::<AgentServerFrame>(b"{"),
            Err(AgentProtocolError::MalformedJson)
        ));
    }

    #[tokio::test]
    async fn frame_reader_survives_select_style_cancellation_mid_frame() {
        // The adapter bridge and the phone subscription loop both drop their read future when
        // another select! branch wins. Deliver frames one byte at a time and drop a freshly
        // polled read future after every byte — every frame must still come out intact and in
        // order.
        let frames = vec![
            AgentServerFrame::Error {
                v: 1,
                code: "first".into(),
            },
            AgentServerFrame::Error {
                v: 1,
                code: "second".into(),
            },
            AgentServerFrame::Error {
                v: 1,
                code: "third".into(),
            },
        ];
        let bytes: Vec<u8> = frames
            .iter()
            .flat_map(|frame| encode_agent_frame(frame).unwrap())
            .collect();
        let (mut writer, mut stream) = tokio::io::duplex(8);
        let mut frame_reader = AgentFrameReader::default();
        let mut received = Vec::new();
        for byte in bytes {
            writer.write_all(&[byte]).await.unwrap();
            let mut read = std::pin::pin!(frame_reader.next(&mut stream));
            let polled =
                std::future::poll_fn(|context| std::task::Poll::Ready(read.as_mut().poll(context)))
                    .await;
            if let std::task::Poll::Ready(result) = polled {
                received.push(decode_agent_body::<AgentServerFrame>(&result.unwrap()).unwrap());
            }
            // `read` drops here mid-frame, exactly as the select! does. Swapping this reader
            // back to `read_agent_frame` makes the drain below time out — bytes lost.
        }
        while received.len() < frames.len() {
            let body = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                frame_reader.next(&mut stream),
            )
            .await
            .expect("stream desynced: bytes were lost to a cancelled read")
            .unwrap();
            received.push(decode_agent_body::<AgentServerFrame>(&body).unwrap());
        }
        assert_eq!(received, frames);
    }

    #[test]
    fn malformed_utf8_deep_nesting_and_decompression_equivalent_size_fail_closed() {
        assert!(matches!(
            decode_agent_body::<AgentServerFrame>(&[0xff]),
            Err(AgentProtocolError::MalformedJson)
        ));
        let deeply_nested = format!("{}0{}", "[".repeat(256), "]".repeat(256));
        assert!(decode_agent_body::<AgentServerFrame>(deeply_nested.as_bytes()).is_err());
        assert!(matches!(
            decode_agent_body::<AgentServerFrame>(&vec![b'x'; MAX_AGENT_FRAME_BYTES + 1]),
            Err(AgentProtocolError::FrameTooLarge)
        ));
    }

    fn managed_fixture() -> Value {
        load_fixture("phase5/agent-managed-v1.json")
    }

    fn managed_hostile_fixture() -> Value {
        load_fixture("phase5/managed-hostile-v1.json")
    }

    fn managed_bounds_fixture() -> Value {
        load_fixture("phase5/managed-bounds-v1.json")
    }

    /// The catalogue rides inside a snapshot, and a snapshot rides inside one 64 KB frame — so
    /// the bounds on the catalogue are only meaningful if the worst list they permit still
    /// leaves a snapshot room for its timeline.
    ///
    /// Measured against the real serializer rather than argued: the numbers here are what a
    /// hostile-but-legal catalogue actually costs, so tightening a bound without re-measuring
    /// trips this rather than being discovered on a phone.
    #[test]
    fn the_largest_legal_catalogue_still_leaves_a_snapshot_most_of_its_frame() {
        let worst = AgentModelOption {
            value: "x".repeat(MAX_MODEL_ID_BYTES),
            display_name: "N".repeat(MAX_MODEL_DISPLAY_NAME_BYTES),
            supports_effort: true,
            supported_effort_levels: (0..MAX_EFFORT_LEVELS_PER_MODEL)
                .map(|_| "e".repeat(MAX_TOKEN_BYTES))
                .collect(),
        };
        worst.validate().unwrap();
        let catalogue: Vec<AgentModelOption> = (0..MAX_MODEL_CATALOGUE_ENTRIES)
            .map(|_| worst.clone())
            .collect();
        validate_model_catalogue(&catalogue).unwrap();

        let mut state = snapshot();
        let bare = serde_json::to_vec(&state).unwrap().len();
        state.models = Some(catalogue);
        state.model = Some("x".repeat(MAX_MODEL_ID_BYTES));
        state.effort = Some("e".repeat(MAX_TOKEN_BYTES));
        state.validate().unwrap();
        let full = serde_json::to_vec(&state).unwrap().len();

        // The whole snapshot, worst catalogue and all, must still fit one frame with room to
        // spare for the timeline window a real session carries.
        assert!(
            full < MAX_AGENT_FRAME_BYTES,
            "{full} bytes must fit one frame"
        );
        // And the catalogue itself must stay a minority of the budget: a quarter is the line,
        // because the timeline previews alone are bounded at 16 KB and 32 KB.
        let catalogue_cost = full - bare;
        assert!(
            catalogue_cost < MAX_AGENT_FRAME_BYTES / 4,
            "the worst legal catalogue costs {catalogue_cost} bytes of a {MAX_AGENT_FRAME_BYTES} byte frame"
        );
    }

    /// The shared fixture carries the model surfaces so both languages decode the same bytes.
    /// A managed snapshot starts knowing no model at all — the SDK names one only once a turn
    /// produces it — and the catalogue, model, and effort all arrive as reported state.
    #[test]
    fn the_shared_managed_fixture_reports_a_catalogue_and_the_model_answering() {
        let mut state = managed_snapshot();
        assert!(
            state.model.is_none(),
            "a managed session starts knowing no model"
        );
        assert!(state.models.is_none());

        let deltas: Vec<AgentSessionDelta> =
            serde_json::from_value(managed_fixture()["deltas"].clone()).unwrap();
        let reported = deltas.last().expect("the fixture carries a model delta");
        reported.validate().unwrap();
        state.revision = reported.base_revision;
        assert_eq!(
            apply_delta(&mut state, reported).unwrap(),
            ReduceOutcome::Applied
        );
        state.validate().unwrap();

        assert_eq!(state.model.as_deref(), Some("claude-opus-5[1m]"));
        assert_eq!(state.effort.as_deref(), Some("xhigh"));
        let models = state.models.expect("the catalogue applies whole");
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].value, "claude-opus-5[1m]");
        assert_eq!(models[0].supported_effort_levels.len(), 5);
        // Absent `supports_effort` reads as no effort choice rather than failing the row.
        assert!(!models[1].supports_effort);
        assert!(models[1].supported_effort_levels.is_empty());
    }

    fn managed_snapshot() -> AgentSessionSnapshot {
        serde_json::from_value(managed_fixture()["snapshot"].clone()).unwrap()
    }

    fn managed_descriptors() -> Vec<AgentSessionDescriptor> {
        serde_json::from_value(managed_fixture()["list"]["sessions"].clone()).unwrap()
    }

    #[test]
    fn managed_canonical_fixture_validates_without_adapter_types() {
        let value = managed_fixture();
        let list: AgentSessionList = serde_json::from_value(value["list"].clone()).unwrap();
        list.validate().unwrap();
        let snapshot = managed_snapshot();
        snapshot.validate().unwrap();
        assert_eq!(
            snapshot.timeline_window.history_boundary.as_deref(),
            Some("resume")
        );
        let workspaces: AgentWorkspaceList =
            serde_json::from_value(value["workspaces"].clone()).unwrap();
        workspaces.validate().unwrap();
        for open in value["lifecycle_opens"].as_array().unwrap() {
            let open: AgentStreamOpen = serde_json::from_value(open.clone()).unwrap();
            open.validate().unwrap();
        }
        for outcome in value["lifecycle_outcomes"].as_array().unwrap() {
            let outcome: LifecycleOutcome = serde_json::from_value(outcome.clone()).unwrap();
            outcome.validate().unwrap();
        }
        for command in value["interaction_response_commands"].as_array().unwrap() {
            let command: AgentCommand = serde_json::from_value(command.clone()).unwrap();
            command.validate().unwrap();
        }
        for interaction in value["permission_cases"].as_array().unwrap() {
            let interaction: PendingInteraction =
                serde_json::from_value(interaction.clone()).unwrap();
            interaction.validate().unwrap();
        }
        // The question shape carries two fields nothing else needs: the chip that names what a
        // question is about, and the consequence of choosing an option. Both are what make the
        // card renderable, so both are pinned here where either language would notice losing one.
        let question: PendingInteraction =
            serde_json::from_value(value["permission_cases"][1].clone()).unwrap();
        assert_eq!(question.kind, "question");
        let ResponseSchema::Questions { questions } = &question.response_schema else {
            panic!("expected a questions schema");
        };
        assert_eq!(questions[0].header.as_deref(), Some("Transport"));
        assert_eq!(questions[0].response_kind, "single_choice");
        assert_eq!(questions[1].response_kind, "multi_choice");
        assert_eq!(
            questions[0].options[0].description.as_deref(),
            Some("Direct QUIC where possible.")
        );
        for receipt in value["receipt_cases"].as_array().unwrap() {
            let receipt: CommandReceipt = serde_json::from_value(receipt.clone()).unwrap();
            receipt.validate().unwrap();
        }
        // Every categorical stored reason validates on a stored descriptor, and an
        // unknown future token stays decode-tolerant (rendering is Swift's job).
        let stored = managed_descriptors().into_iter().nth(1).unwrap();
        assert_eq!(stored.presence, "stored");
        for reason in value["stored_reason_cases"].as_array().unwrap() {
            let mut descriptor = stored.clone();
            descriptor.stored_reason = Some(reason.as_str().unwrap().to_owned());
            descriptor.validate().unwrap();
        }
        let mut future = stored.clone();
        future.stored_reason = Some("future_reason".into());
        future.validate().unwrap();
        let released = managed_descriptors().into_iter().nth(2).unwrap();
        assert_eq!(released.stored_reason.as_deref(), Some("released"));
        assert_eq!(
            released.terminal_fallback.handback_session.as_deref(),
            Some("ciao-fixture-a1b2c3d4")
        );
        assert_eq!(
            released.capabilities.terminal_continuity,
            "resumable_session"
        );
        // Attached descriptors serialize without any managed-only key, keeping old
        // peers byte-compatible.
        let attached: AgentSessionDescriptor =
            serde_json::from_value(fixture()["list"]["sessions"][0].clone()).unwrap();
        let encoded = serde_json::to_string(&attached).unwrap();
        assert!(!encoded.contains("stored_reason"));
        assert!(!encoded.contains("history_boundary"));
    }

    #[test]
    fn managed_reducer_properties_hold_across_orderings() {
        let value = managed_fixture();
        let deltas: Vec<AgentSessionDelta> =
            serde_json::from_value(value["deltas"].clone()).unwrap();
        let permutations = [
            vec![0, 1, 2],
            vec![0, 0, 1, 2],
            vec![1, 0, 2],
            vec![2, 0],
            vec![0, 2, 1],
        ];
        for order in permutations {
            let mut state = managed_snapshot();
            for index in order {
                let _ = apply_delta(&mut state, &deltas[index]);
                // A managed session never grows a terminal route, whatever the order.
                assert_eq!(state.terminal_fallback.continuity, "unavailable");
                assert_eq!(state.capabilities.terminal_continuity, "unavailable");
                if state
                    .pending_interactions
                    .iter()
                    .any(PendingInteraction::is_unresolved_blocking)
                {
                    assert!(matches!(state.turn, TurnState::AwaitingInteraction { .. }));
                }
            }
        }
        // The full ordered run resolves the permission and upgrades the prompt
        // receipt only with replay evidence attached.
        let mut state = managed_snapshot();
        for delta in &deltas {
            assert_eq!(
                apply_delta(&mut state, delta).unwrap(),
                ReduceOutcome::Applied
            );
        }
        assert!(state.pending_interactions.is_empty());
        let receipt = &state.latest_command_receipts[0];
        assert_eq!(receipt.state, "applied");
        assert_eq!(
            receipt.application_evidence.as_deref(),
            Some("replay_correlated")
        );
    }

    #[test]
    fn managed_hostile_cases_fail_or_render_unsupported_as_declared() {
        let hostile = managed_hostile_fixture();
        let cases = hostile["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 12);
        let live = managed_descriptors().into_iter().next().unwrap();
        let stored = managed_descriptors().into_iter().nth(1).unwrap();

        // Unknown topology/presence tokens decode tolerantly; Swift renders them
        // as unsupported rather than crashing or gaining authority.
        let mut unknown_topology = live.clone();
        unknown_topology.topology = cases[0]["topology"].as_str().unwrap().to_owned();
        unknown_topology.validate().unwrap();
        let mut unknown_presence = live.clone();
        unknown_presence.presence = cases[1]["presence"].as_str().unwrap().to_owned();
        unknown_presence.validate().unwrap();

        let mut reason_on_live = live.clone();
        reason_on_live.stored_reason = Some(cases[2]["stored_reason"].as_str().unwrap().to_owned());
        assert!(reason_on_live.validate().is_err());

        let mut stored_running = stored.clone();
        stored_running.turn = TurnState::Running {
            run_id: "run-x".into(),
            activity: "responding".into(),
        };
        stored_running.observation.coverage = "authoritative".into();
        assert!(stored_running.validate().is_err());

        let mut stored_commands = stored.clone();
        stored_commands.capabilities.commands.prompt = true;
        assert!(stored_commands.validate().is_err());

        // A takeover verb on anything but an attached row is a fabricated offer.
        let mut stored_takeover = stored.clone();
        stored_takeover.takeover = Some("promote".into());
        assert!(stored_takeover.validate().is_err());

        let mut stored_attached = stored.clone();
        stored_attached.topology = "attached".into();
        assert!(stored_attached.validate().is_err());

        let mut managed_exact = live.clone();
        managed_exact.capabilities.terminal_continuity = "exact_live".into();
        managed_exact.terminal_fallback = TerminalFallback {
            continuity: "exact_live".into(),
            route_id: Some("route-fabricated".into()),
            availability_reason: None,
            handback_session: None,
            resume_command: None,
        };
        assert!(managed_exact.validate().is_err());

        let released = managed_descriptors().into_iter().nth(2).unwrap();
        let mut invalid_handback = released.clone();
        invalid_handback.terminal_fallback.handback_session = Some("../../bad".into());
        assert!(invalid_handback.validate().is_err());
        let mut ambiguous_handback = released;
        ambiguous_handback.terminal_fallback.route_id = Some("route-too".into());
        assert!(ambiguous_handback.validate().is_err());

        let mut state = managed_snapshot();
        let fabrication: AgentSessionDelta =
            serde_json::from_value(managed_fixture()["hostile_route_delta"].clone()).unwrap();
        assert!(apply_delta(&mut state, &fabrication).is_err());

        let oversized_label = WorkspaceDescriptor {
            workspace_id: "workspace-x".into(),
            display_label: "x".repeat(cases[8]["declared_label_bytes"].as_u64().unwrap() as usize),
        };
        assert!(oversized_label.validate().is_err());
        let oversized_list = AgentWorkspaceList {
            v: 1,
            message_type: "agent_workspace_list".into(),
            workspaces: (0..cases[9]["declared_count"].as_u64().unwrap())
                .map(|index| WorkspaceDescriptor {
                    workspace_id: format!("workspace-{index}"),
                    display_label: "Fixture".into(),
                })
                .collect(),
            omitted_workspaces: 0,
            scan_incomplete: false,
        };
        assert!(oversized_list.validate().is_err());

        let opens: Vec<AgentStreamOpen> =
            serde_json::from_value(managed_fixture()["lifecycle_opens"].clone()).unwrap();
        let mut missing_capability = opens[1].clone();
        missing_capability.capabilities = vec![CAPABILITY_AGENT_SESSION_V1.into()];
        assert!(matches!(
            missing_capability.validate(),
            Err(AgentProtocolError::InvalidValue)
        ));
        let mut unknown_operation = opens[1].clone();
        unknown_operation.operation = cases[11]["operation"].as_str().unwrap().to_owned();
        assert!(matches!(
            unknown_operation.validate(),
            Err(AgentProtocolError::UnexpectedMessage)
        ));
    }

    fn adopted_fixture() -> Value {
        load_fixture("phase6/agent-adopted-v1.json")
    }

    fn adopted_hostile_fixture() -> Value {
        load_fixture("phase6/adopted-hostile-v1.json")
    }

    fn adopted_descriptor() -> AgentSessionDescriptor {
        serde_json::from_value(adopted_fixture()["list"]["sessions"][0].clone()).unwrap()
    }

    #[test]
    fn adopted_canonical_fixture_validates_without_adapter_types() {
        let value = adopted_fixture();
        let list: AgentSessionList = serde_json::from_value(value["list"].clone()).unwrap();
        list.validate().unwrap();
        let snapshot: AgentSessionSnapshot =
            serde_json::from_value(value["snapshot"].clone()).unwrap();
        snapshot.validate().unwrap();
        // The write surface is the point of the topology: steer and interrupt advertised,
        // permission answerable, and the way out is resuming the conversation, not a pane.
        assert!(snapshot.capabilities.commands.prompt);
        assert!(snapshot.capabilities.commands.steer);
        assert!(snapshot.capabilities.commands.interrupt);
        assert!(snapshot.capabilities.interactions.permission.enabled);
        assert_eq!(
            snapshot.capabilities.terminal_continuity,
            "resumable_session"
        );
        assert_eq!(snapshot.control_owner, "none");
    }

    #[test]
    fn adopted_hostile_cases_fail_as_declared() {
        // Spec 013 §9: adopted is live-only and its continuity is resumable_session — an
        // adopted session exists only while Ciao holds the thread, and the way back to a
        // terminal is `codex resume`, never a claimed pane.
        let hostile = adopted_hostile_fixture();
        assert_eq!(hostile["cases"].as_array().unwrap().len(), 5);
        let base = adopted_descriptor();

        let mut stored = base.clone();
        stored.presence = "stored".into();
        assert!(stored.validate().is_err());

        let mut unavailable = base.clone();
        unavailable.capabilities.terminal_continuity = "unavailable".into();
        unavailable.terminal_fallback = TerminalFallback {
            continuity: "unavailable".into(),
            route_id: None,
            availability_reason: None,
            handback_session: None,
            resume_command: None,
        };
        assert!(unavailable.validate().is_err());

        let mut exact = base;
        exact.capabilities.terminal_continuity = "exact_live".into();
        exact.terminal_fallback = TerminalFallback {
            continuity: "exact_live".into(),
            route_id: Some("route-fabricated".into()),
            availability_reason: None,
            handback_session: None,
            resume_command: None,
        };
        assert!(exact.validate().is_err());
    }

    #[test]
    fn adopted_pickup_takes_promotes_shape_behind_its_own_capability() {
        let open = |capabilities: Vec<String>, session: Option<&str>, command: Option<&str>| {
            AgentStreamOpen {
                v: AGENT_PROTOCOL_VERSION,
                message_type: "agent_stream_open".into(),
                client_instance_id: "client-fixture-1".into(),
                operation: "agent.adopted.pickup".into(),
                capabilities,
                session_id: session.map(str::to_owned),
                before_sequence: None,
                page_limit: None,
                workspace_id: None,
                lifecycle_command_id: command.map(str::to_owned),
                expected_generation: None,
            }
        };
        let both = vec![
            CAPABILITY_AGENT_SESSION_V1.to_owned(),
            CAPABILITY_AGENT_SESSION_ADOPTED_V1.to_owned(),
        ];
        open(both.clone(), Some("codex-adopted-abc"), Some("command-1"))
            .validate()
            .unwrap();
        // Which conversation and which command are both required; anything extra is refused.
        assert!(
            open(both.clone(), None, Some("command-1"))
                .validate()
                .is_err()
        );
        assert!(
            open(both.clone(), Some("codex-adopted-abc"), None)
                .validate()
                .is_err()
        );
        // The verb is gated on its own capability, so an app that never learned it cannot
        // send it half-formed.
        assert!(
            open(
                vec![CAPABILITY_AGENT_SESSION_V1.to_owned()],
                Some("codex-adopted-abc"),
                Some("command-1"),
            )
            .validate()
            .is_err()
        );
    }

    /// The flag has to be invisible when false. An app built before it validates the exact key
    /// set of every frame it decodes and refuses one carrying a key it does not know, and hosts
    /// update on their own while phones wait on TestFlight — so a host that always sent this
    /// would break the New agent sheet on every phone that had not caught up yet.
    #[test]
    fn the_incomplete_scan_flag_stays_off_the_wire_until_it_is_true() {
        let frame = |scan_incomplete| AgentServerFrame::WorkspaceList {
            v: AGENT_PROTOCOL_VERSION,
            workspaces: vec![WorkspaceDescriptor {
                workspace_id: "workspace-a".into(),
                display_label: "ciao".into(),
            }],
            omitted_workspaces: 0,
            scan_incomplete,
        };
        // Past the four-byte length prefix: this is about the JSON body's keys.
        let encoded = |scan_incomplete| -> Value {
            let framed = encode_agent_frame(&frame(scan_incomplete)).unwrap();
            serde_json::from_slice(&framed[4..]).unwrap()
        };

        let complete = encoded(false);
        assert!(
            complete.get("scan_incomplete").is_none(),
            "a complete scan must send the frame an older app already reads: {complete}"
        );
        assert_eq!(encoded(true)["scan_incomplete"], Value::Bool(true));
        // And the same tolerance in reverse, for a frame from a host that predates the field.
        assert_eq!(
            serde_json::from_value::<AgentServerFrame>(complete).unwrap(),
            frame(false)
        );
    }

    #[test]
    fn managed_bounds_are_exact_and_lifecycle_param_shapes_are_strict() {
        let bounds = managed_bounds_fixture();
        for (name, actual) in [
            ("workspace_list_count", MAX_WORKSPACE_LIST_ENTRIES),
            ("workspace_list_bytes", MAX_WORKSPACE_LIST_BYTES),
            ("workspace_display_label_bytes", MAX_WORKSPACE_LABEL_BYTES),
            ("lifecycle_receipts", MAX_LIFECYCLE_RECEIPTS),
        ] {
            assert_eq!(bounds[name].as_u64().unwrap(), actual as u64, "{name}");
        }
        let opens: Vec<AgentStreamOpen> =
            serde_json::from_value(managed_fixture()["lifecycle_opens"].clone()).unwrap();
        // Each lifecycle operation rejects a missing required parameter and any
        // parameter borrowed from another operation.
        let mut start_missing_workspace = opens[1].clone();
        start_missing_workspace.workspace_id = None;
        assert!(start_missing_workspace.validate().is_err());
        let mut start_with_session = opens[1].clone();
        start_with_session.session_id = Some("managed-live".into());
        assert!(start_with_session.validate().is_err());
        let mut stop_missing_generation = opens[2].clone();
        stop_missing_generation.expected_generation = None;
        assert!(stop_missing_generation.validate().is_err());
        let mut stop_zero_generation = opens[2].clone();
        stop_zero_generation.expected_generation = Some(0);
        assert!(stop_zero_generation.validate().is_err());
        let mut resume_with_generation = opens[3].clone();
        resume_with_generation.expected_generation = Some(2);
        assert!(resume_with_generation.validate().is_err());
        let mut list_with_workspace = opens[0].clone();
        list_with_workspace.workspace_id = Some("workspace-a".into());
        assert!(list_with_workspace.validate().is_err());
        // Promote takes resume's parameters. Without an arm of its own it fell through to
        // the unknown-operation reject, so every takeover from a phone was refused as a
        // malformed handshake while the CLI's IPC route, which skips this, worked.
        let mut promote = opens[3].clone();
        promote.operation = "agent.managed.promote".into();
        assert!(promote.validate().is_ok(), "a takeover must reach the host");
        let mut promote_with_generation = promote.clone();
        promote_with_generation.expected_generation = Some(2);
        assert!(promote_with_generation.validate().is_err());
        // Release is the other half of the round trip and reaches the host the same way. A
        // lifecycle verb missing from this table is refused before dispatch, which is
        // indistinguishable from the host never being asked.
        let mut release = opens[3].clone();
        release.operation = "agent.managed.release".into();
        assert!(
            release.validate().is_ok(),
            "a handback must reach the host from a client, not only over IPC"
        );
        let mut release_with_workspace = release.clone();
        release_with_workspace.workspace_id = Some("workspace-a".into());
        assert!(release_with_workspace.validate().is_err());
    }

    #[test]
    fn interaction_response_gating_follows_interaction_capabilities() {
        let snapshot = managed_snapshot();
        let command: AgentCommand =
            serde_json::from_value(managed_fixture()["interaction_response_commands"][0].clone())
                .unwrap();
        // Command capabilities alone never permit a response; the interaction
        // capability does, and a stored session permits nothing.
        assert!(!snapshot.capabilities.commands.permits(&command.kind));
        assert!(snapshot.capabilities.permits(&command.kind));
        assert!(
            snapshot
                .capabilities
                .permits(&AgentCommandKind::Prompt { text: "hi".into() })
        );
        let stored = managed_descriptors().into_iter().nth(1).unwrap();
        assert!(!stored.capabilities.permits(&command.kind));
        assert!(
            !stored
                .capabilities
                .permits(&AgentCommandKind::Prompt { text: "hi".into() })
        );
        let mut none = snapshot.capabilities.clone();
        none.interactions = InteractionCapabilities::none();
        assert!(!none.permits(&command.kind));
    }
}
