//! Carrying evidence forward across a Codex minor (Spec 017 §4.3, Phase 3).
//!
//! A 0.x minor is a breaking change by convention, so `classify_vendor_version` refuses it on
//! the version string alone. But the convention is a prior, not a fact: Codex publishes its own
//! JSON schema, and `integrations/codex/generate-conformance.mjs` already distills that schema
//! down to the read-set this adapter depends on and pins the result in `protocol-pins.json`.
//! This module is the same distillation, ported to Rust and run *on the user's machine at first
//! contact with an unseen version*: extract, distill, compare. Every read-set field
//! byte-identical → the pin's grounding evidence carries to the new version — state `carried`,
//! full capabilities, zero model turns, no release. Anything the adapter reads differing → the
//! version stays refused exactly as before, and each changed field is named in the drift
//! ledger.
//!
//! The verdict is cached in `run/codex-carry.json`, keyed by the binary's size, mtime, and
//! SHA-256. This is deliberately not the parked "per-version cache of probe verdicts"
//! (`agent_protocol.rs` records why that was rejected): a cached *probe* verdict goes stale
//! silently because the thing it judged can change behind it. A verdict keyed by the digest of
//! the artifact it judged cannot go stale — the artifact changes, the key misses, the check
//! reruns. Content-addressing is the property whose absence got the other design parked.
//!
//! The `.mjs` stays the dev-side generator and the source of truth for the pinned extract; the
//! opt-in lock test (`CIAO_TEST_CODEX_CLI=1`) proves this port reproduces its digest and lists
//! byte-for-byte against the real pinned binary.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::agent_protocol::{VendorVersionState, classify_vendor_version};

pub(crate) const VERDICT_FILE_NAME: &str = "codex-carry.json";
const VERDICT_FILE_VERSION: u8 = 1;
const MAX_VERDICT_BYTES: u64 = 16 * 1024;
/// Schema generation is file output only and finishes well under a second on the grounded
/// machine; ten seconds is process-start headroom, not a second budget.
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(10);
/// A failed or timed-out check is retried on a later sighting, not in a loop.
const RECHECK_BACKOFF: Duration = Duration::from_secs(600);

// ---------------------------------------------------------------------------
// The distilled extract, matching protocol-pins.json field for field.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Counts {
    pub(crate) client_methods: u64,
    pub(crate) server_notifications: u64,
}

/// One distilled protocol extract. Deserializes from the embedded `protocol-pins.json`
/// (tolerating its `pin`/`generatedBy` provenance fields) and is produced fresh by
/// [`distill_schema_dir`]. Missing lists in a future schema deserialize/distill as empty
/// rather than erroring — an absent definition *is* a read-set change, and naming it beats
/// refusing to look.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PinExtract {
    pub(crate) counts: Counts,
    #[serde(default)]
    pub(crate) required_client_methods: Vec<String>,
    #[serde(default)]
    pub(crate) adopted_server_requests: Vec<String>,
    #[serde(default)]
    pub(crate) command_execution_decisions: Vec<String>,
    #[serde(default)]
    pub(crate) file_change_decisions: Vec<String>,
    #[serde(default)]
    pub(crate) adopted_notifications: Vec<String>,
    #[serde(default)]
    pub(crate) steer_required_params: Vec<String>,
    #[serde(default)]
    pub(crate) interrupt_required_params: Vec<String>,
    #[serde(default)]
    pub(crate) thread_start_sandbox_is_mode: bool,
    #[serde(default)]
    pub(crate) sandbox_modes: Vec<String>,
    #[serde(default)]
    pub(crate) hook_event_names: Vec<String>,
    #[serde(default)]
    pub(crate) hook_sources: Vec<String>,
    #[serde(default)]
    pub(crate) hook_run_status: Vec<String>,
    #[serde(default)]
    pub(crate) thread_item_types: Vec<String>,
    #[serde(default)]
    pub(crate) thread_status_types: Vec<String>,
    #[serde(default)]
    pub(crate) turn_status: Vec<String>,
    #[serde(default)]
    pub(crate) thread_active_flags: Vec<String>,
    pub(crate) schema_digest: String,
}

impl PinExtract {
    /// The read-set fields that decide the verdict, by their pins-file names. `counts` and
    /// `schemaDigest` are deliberately not here: they describe the whole protocol, and the
    /// 0.147.0 bump proved the point — both moved while every list the adapter reads stayed
    /// byte-identical, and the human verdict was "safe". This is that verdict, mechanized.
    pub(crate) fn read_set_changes(&self, other: &Self) -> Vec<&'static str> {
        let mut changed = Vec::new();
        macro_rules! diff {
            ($field:ident, $name:literal) => {
                if self.$field != other.$field {
                    changed.push($name);
                }
            };
        }
        diff!(required_client_methods, "requiredClientMethods");
        diff!(adopted_server_requests, "adoptedServerRequests");
        diff!(command_execution_decisions, "commandExecutionDecisions");
        diff!(file_change_decisions, "fileChangeDecisions");
        diff!(adopted_notifications, "adoptedNotifications");
        diff!(steer_required_params, "steerRequiredParams");
        diff!(interrupt_required_params, "interruptRequiredParams");
        diff!(thread_start_sandbox_is_mode, "threadStartSandboxIsMode");
        diff!(sandbox_modes, "sandboxModes");
        diff!(hook_event_names, "hookEventNames");
        diff!(hook_sources, "hookSources");
        diff!(hook_run_status, "hookRunStatus");
        diff!(thread_item_types, "threadItemTypes");
        diff!(thread_status_types, "threadStatusTypes");
        diff!(turn_status, "turnStatus");
        diff!(thread_active_flags, "threadActiveFlags");
        changed
    }
}

/// The pinned extract this build ships, parsed once from the same embedded bytes the
/// item-novelty check reads. `None` only if the embedded file is unreadable, in which case
/// carrying is simply unavailable — a broken diagnostic must not admit anything.
pub(crate) fn embedded_extract() -> Option<&'static PinExtract> {
    static EMBEDDED: LazyLock<Option<PinExtract>> =
        LazyLock::new(|| serde_json::from_str(crate::codex_adapter::PROTOCOL_PINS).ok());
    EMBEDDED.as_ref()
}

// ---------------------------------------------------------------------------
// Distillation: the .mjs, faithfully.
// ---------------------------------------------------------------------------

/// A discriminant is spelled `const` for some variants and a one-value `enum` for others.
fn discriminant(schema: &Value) -> Option<&str> {
    if let Some(constant) = schema.get("const").and_then(Value::as_str) {
        return Some(constant);
    }
    match schema.get("enum").and_then(Value::as_array) {
        Some(values) if values.len() == 1 => values[0].as_str(),
        _ => None,
    }
}

fn methods_of(document: &Value) -> Vec<String> {
    let mut methods: Vec<String> = document
        .get("oneOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|variant| discriminant(variant.get("properties")?.get("method")?))
        .map(str::to_owned)
        .collect();
    methods.sort();
    methods
}

fn variants_of(definitions: &Value, name: &str) -> Vec<String> {
    let definition = &definitions[name];
    let mut variants: Vec<String> = definition
        .get("oneOf")
        .or_else(|| definition.get("anyOf"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|variant| discriminant(variant.get("properties")?.get("type")?))
        .map(str::to_owned)
        .collect();
    variants.sort();
    variants
}

fn enum_of(definitions: &Value, name: &str) -> Vec<String> {
    let mut values: Vec<String> = definitions[name]
        .get("enum")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    values.sort();
    values
}

/// The params schema for one client method, `$ref`s resolved against the document's own
/// definitions — the generator inlines some and references others.
fn params_of(client_request: &Value, method: &str) -> Value {
    let params = client_request
        .get("oneOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|variant| {
            variant
                .get("properties")
                .and_then(|properties| properties.get("method"))
                .and_then(discriminant)
                == Some(method)
        })
        .and_then(|variant| variant.get("properties")?.get("params"))
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    if let Some(reference) = params.get("$ref").and_then(Value::as_str) {
        let name = reference.rsplit('/').next().unwrap_or_default();
        return client_request
            .get("definitions")
            .and_then(|definitions| definitions.get(name))
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default()));
    }
    params
}

fn required_params_of(client_request: &Value, method: &str) -> Vec<String> {
    let mut required: Vec<String> = params_of(client_request, method)
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    required.sort();
    required
}

fn decisions_of(document: &Value, name: &str) -> Vec<String> {
    let mut decisions: Vec<String> = document
        .get("definitions")
        .and_then(|definitions| definitions.get(name))
        .and_then(|definition| definition.get("oneOf"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(
            |variant| match variant.get("enum").and_then(Value::as_array) {
                Some(values) => values.first().and_then(Value::as_str),
                None => variant.get("const").and_then(Value::as_str),
            },
        )
        .map(str::to_owned)
        .collect();
    decisions.sort();
    decisions
}

fn keep_listed(fixed: &[&str], available: &[String]) -> Vec<String> {
    // Filter, not sort: the pins file preserves the hardcoded order of the lists the adapter
    // depends on, and this must byte-match it.
    fixed
        .iter()
        .filter(|method| available.iter().any(|candidate| candidate == *method))
        .map(|method| (*method).to_owned())
        .collect()
}

/// Distills one directory of `generate-json-schema` output exactly as the `.mjs` does.
pub(crate) fn distill_schema_dir(directory: &Path) -> Result<PinExtract> {
    let read = |name: &str| -> Result<Value> {
        let bytes = std::fs::read(directory.join(name)).with_context(|| format!("read {name}"))?;
        serde_json::from_slice(&bytes).with_context(|| format!("parse {name}"))
    };
    let client_request = read("ClientRequest.json")?;
    let server_notification = read("ServerNotification.json")?;
    let server_request = read("ServerRequest.json")?;
    let definitions = server_notification
        .get("definitions")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));

    let client_methods = methods_of(&client_request);
    let server_methods = methods_of(&server_notification);
    let server_request_methods = methods_of(&server_request);

    let sandbox = params_of(&client_request, "thread/start")
        .get("properties")
        .and_then(|properties| properties.get("sandbox"))
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));

    let mut sandbox_modes: Vec<String> = client_request
        .get("definitions")
        .and_then(|definitions| definitions.get("SandboxMode"))
        .and_then(|definition| definition.get("enum"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    sandbox_modes.sort();

    Ok(PinExtract {
        counts: Counts {
            client_methods: client_methods.len() as u64,
            server_notifications: server_methods.len() as u64,
        },
        required_client_methods: keep_listed(
            &[
                "thread/read",
                "thread/list",
                "hooks/list",
                "thread/resume",
                "thread/archive",
                "turn/start",
                "turn/steer",
                "turn/interrupt",
            ],
            &client_methods,
        ),
        adopted_server_requests: keep_listed(
            &[
                "item/commandExecution/requestApproval",
                "item/fileChange/requestApproval",
                "item/tool/requestUserInput",
            ],
            &server_request_methods,
        ),
        command_execution_decisions: decisions_of(
            &read("CommandExecutionRequestApprovalResponse.json")?,
            "CommandExecutionApprovalDecision",
        ),
        file_change_decisions: decisions_of(
            &read("FileChangeRequestApprovalResponse.json")?,
            "FileChangeApprovalDecision",
        ),
        adopted_notifications: keep_listed(
            &[
                "turn/started",
                "turn/completed",
                "item/started",
                "item/completed",
                "item/agentMessage/delta",
            ],
            &server_methods,
        ),
        steer_required_params: required_params_of(&client_request, "turn/steer"),
        interrupt_required_params: required_params_of(&client_request, "turn/interrupt"),
        thread_start_sandbox_is_mode: serde_json::to_string(&sandbox)
            .unwrap_or_default()
            .contains("SandboxMode"),
        sandbox_modes,
        hook_event_names: enum_of(&definitions, "HookEventName"),
        hook_sources: enum_of(&definitions, "HookSource"),
        hook_run_status: enum_of(&definitions, "HookRunStatus"),
        thread_item_types: variants_of(&definitions, "ThreadItem"),
        thread_status_types: variants_of(&definitions, "ThreadStatus"),
        turn_status: enum_of(&definitions, "TurnStatus"),
        thread_active_flags: enum_of(&definitions, "ThreadActiveFlag"),
        schema_digest: schema_digest(directory)?,
    })
}

/// SHA-256 over `name \0 canonical(json) \n` for every file, names sorted — byte-compatible
/// with the `.mjs` so the two sides pin one number.
fn schema_digest(directory: &Path) -> Result<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .context("read schema directory")?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut hasher = Sha256::new();
    for name in names {
        let full = directory.join(&name);
        if !full.is_file() {
            continue;
        }
        let value: Value = serde_json::from_slice(&std::fs::read(&full)?)
            .with_context(|| format!("parse {name}"))?;
        let mut chunk = String::new();
        chunk.push_str(&name);
        chunk.push('\u{0}');
        canonical(&value, &mut chunk);
        chunk.push('\n');
        hasher.update(chunk.as_bytes());
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Key-sorted JSON, spelled the way `JSON.stringify` spells scalars, so a digest computed here
/// equals one computed by node over the same document.
fn canonical(value: &Value, out: &mut String) {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Explicit sort: correct whether or not serde_json preserves insertion order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                js_string(key, out);
                out.push(':');
                canonical(&map[key], out);
            }
            out.push('}');
        }
        Value::String(text) => js_string(text, out),
        Value::Number(number) => js_number(number, out),
        Value::Bool(boolean) => out.push_str(if *boolean { "true" } else { "false" }),
        Value::Null => out.push_str("null"),
    }
}

/// `JSON.stringify` string escaping: the named escapes, lowercase `\u00xx` for remaining
/// control characters, everything else raw.
fn js_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => out.push(character),
        }
    }
    out.push('"');
}

/// `JSON.stringify` number formatting: integral doubles drop their fraction (`1.0` → `1`,
/// `-0` → `0`), and JS switches to exponent notation at `>= 1e21` and `< 1e-6`.
///
/// ponytail: exponent mantissas trust Rust's shortest form plus a `+` where JS writes one.
/// Real schema files carry small integers; anything more exotic fails the opt-in lock test
/// loudly rather than digesting differently in silence.
fn js_number(number: &serde_json::Number, out: &mut String) {
    if let Some(value) = number.as_i64() {
        out.push_str(&value.to_string());
        return;
    }
    if let Some(value) = number.as_u64() {
        out.push_str(&value.to_string());
        return;
    }
    let value = number.as_f64().unwrap_or(0.0);
    if value == 0.0 {
        out.push('0');
        return;
    }
    let magnitude = value.abs();
    if value.fract() == 0.0 && magnitude < 1e21 {
        out.push_str(&format!("{value:.0}"));
        return;
    }
    if !(1e-6..1e21).contains(&magnitude) {
        let exponential = format!("{value:e}");
        match exponential.split_once('e') {
            Some((mantissa, exponent)) if !exponent.starts_with('-') => {
                out.push_str(&format!("{mantissa}e+{exponent}"));
            }
            _ => out.push_str(&exponential),
        }
        return;
    }
    out.push_str(&value.to_string());
}

// ---------------------------------------------------------------------------
// Running the extraction against an installed binary.
// ---------------------------------------------------------------------------

/// Runs `codex app-server generate-json-schema` bounded and distills the result, after
/// confirming the binary still answers as the sighted version — a binary that changed between
/// sighting and check must not be judged under the old number.
pub(crate) async fn extract_installed(binary: &Path, expected_version: &str) -> Result<PinExtract> {
    let version_output = tokio::time::timeout(
        EXTRACT_TIMEOUT,
        tokio::process::Command::new(binary)
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| anyhow!("codex --version timed out"))??;
    let version = crate::codex_hook::parse_codex_version_output(&version_output)?;
    if version != expected_version {
        bail!("codex answers {version}, not the sighted {expected_version}");
    }
    let directory = ScratchDir::create()?;
    let status = tokio::time::timeout(
        EXTRACT_TIMEOUT,
        tokio::process::Command::new(binary)
            .args(["app-server", "generate-json-schema", "--out"])
            .arg(directory.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(|_| anyhow!("schema generation timed out"))??;
    if !status.success() {
        bail!("schema generation failed: {status}");
    }
    let path = directory.path().to_owned();
    tokio::task::spawn_blocking(move || {
        let distilled = distill_schema_dir(&path);
        drop(directory);
        distilled
    })
    .await
    .context("distillation task")?
}

/// A fresh randomly named scratch directory, removed on drop. `tempfile` is a dev-dependency
/// here and this is the one production caller; sixteen random bytes and `create_dir` (which
/// refuses an existing path) cover what it would be pulled in for.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn create() -> Result<Self> {
        let nonce = rand::random::<[u8; 16]>();
        let name: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("ciao-codex-schema-{name}"));
        std::fs::create_dir(&path).context("schema scratch directory")?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// The verdict cache: content-addressed, stat-validated.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BinaryIdentity {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) mtime: u64,
    pub(crate) sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CarryVerdict {
    pub(crate) v: u8,
    /// The vendor version this verdict judged.
    pub(crate) version: String,
    pub(crate) binary: BinaryIdentity,
    /// Whether every read-set field matched the embedded pin extract.
    pub(crate) carried: bool,
    /// The pins-file names of the read-set fields that differed, when any did.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) changed: Vec<String>,
    /// The fresh extract's whole-protocol digest, for the human reading the file.
    pub(crate) schema_digest: String,
    pub(crate) checked_at: u64,
}

fn verdict_path(run_dir: &Path) -> PathBuf {
    run_dir.join(VERDICT_FILE_NAME)
}

/// Loads a persisted verdict, tolerantly: missing, oversized, malformed, or wrong-version
/// files read as no verdict at all.
pub(crate) fn load_verdict(run_dir: &Path) -> Option<CarryVerdict> {
    let path = verdict_path(run_dir);
    let metadata = std::fs::metadata(&path).ok()?;
    if metadata.len() > MAX_VERDICT_BYTES {
        return None;
    }
    let verdict: CarryVerdict = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
    (verdict.v == VERDICT_FILE_VERSION).then_some(verdict)
}

fn store_verdict(run_dir: &Path, verdict: &CarryVerdict) {
    if let Ok(bytes) = serde_json::to_vec(verdict)
        && let Err(error) = crate::storage::atomic_write_private(&verdict_path(run_dir), &bytes)
    {
        tracing::debug!(error = %error, "codex carry verdict write failed");
    }
}

fn binary_stat(path: &Path) -> Option<(u64, u64)> {
    let metadata = std::fs::metadata(path).ok()?;
    let mtime = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((metadata.len(), mtime))
}

/// Whether a stored verdict still describes this binary: same recorded path, same size, same
/// mtime. The SHA-256 in the file is provenance for the stat pair, the same memoization shape
/// the managed digest gate uses — a swapped binary misses on stat and is re-verified in full.
pub(crate) fn verdict_covers(verdict: &CarryVerdict, version: &str, binary: &Path) -> bool {
    if verdict.version != version || verdict.binary.path != binary.to_string_lossy() {
        return false;
    }
    binary_stat(binary)
        .is_some_and(|(size, mtime)| size == verdict.binary.size && mtime == verdict.binary.mtime)
}

/// The carry-aware state for an explicitly located installation — the CLI paths use this with
/// real `CiaoPaths` in hand.
pub(crate) fn state_for(
    version: &str,
    run_dir: &Path,
    binary: Option<&Path>,
) -> VendorVersionState {
    let classified = classify_vendor_version(version, crate::codex_adapter::PINNED_CODEX_VERSION);
    if classified != VendorVersionState::Unsupported {
        return classified;
    }
    if !carry_eligible(version) {
        return classified;
    }
    let Some(binary) = binary else {
        return classified;
    };
    // `codex_binary` answers the bare name when PATH resolution worked; the verdict compares
    // and stats the real file.
    let binary = resolve_on_path(binary).unwrap_or_else(|| binary.to_owned());
    match load_verdict(run_dir) {
        Some(verdict) if verdict_covers(&verdict, version, &binary) && verdict.carried => {
            VendorVersionState::Carried
        }
        _ => classified,
    }
}

/// Only a later minor of the pinned major is worth checking — the same band the shared
/// registration shell enforces before it ever asks a prover.
pub(crate) fn carry_eligible(version: &str) -> bool {
    crate::agent_protocol::later_minor_of_tested_major(
        version,
        crate::codex_adapter::PINNED_CODEX_VERSION,
    )
}

// ---------------------------------------------------------------------------
// Process-wide binding, mirroring drift::bind: hooks read, the daemon also checks.
// ---------------------------------------------------------------------------

struct Bound {
    paths: crate::storage::CiaoPaths,
    checks_enabled: bool,
    /// Unix-seconds of the last attempted check per version, so a failing extraction is
    /// retried on a later sighting rather than in a loop.
    attempts: HashMap<String, u64>,
    in_flight: bool,
}

static BOUND: LazyLock<Mutex<Option<Bound>>> = LazyLock::new(|| Mutex::new(None));

/// Points this process at its Ciao paths. The daemon passes `checks_enabled: true` and gains
/// first-contact verification; hook processes pass `false` and only ever read the verdict.
pub(crate) fn bind(paths: &crate::storage::CiaoPaths, checks_enabled: bool) {
    let mut bound = match BOUND.lock() {
        Ok(bound) => bound,
        Err(poisoned) => poisoned.into_inner(),
    };
    *bound = Some(Bound {
        paths: paths.clone(),
        checks_enabled,
        attempts: HashMap::new(),
        in_flight: false,
    });
}

/// Whether a sighted version's evidence has been carried on this machine. The read the shared
/// registration shell and the hook gate consult; unbound processes answer no.
pub(crate) fn is_carried(version: &str) -> bool {
    let bound = match BOUND.lock() {
        Ok(bound) => bound,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(bound) = bound.as_ref() else {
        return false;
    };
    let binary = crate::codex_integration::codex_binary(&bound.paths);
    state_for(version, &bound.paths.run_dir, binary.as_deref()) == VendorVersionState::Carried
}

/// First contact, from the daemon's registration path: an eligible unproven version schedules
/// one bounded background verification. Non-blocking, deduplicated, backed off; no-op in any
/// process that did not opt into checks.
pub(crate) fn note_sighting(version: &str) {
    if !carry_eligible(version) {
        return;
    }
    let (paths, version) = {
        let mut bound = match BOUND.lock() {
            Ok(bound) => bound,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(bound) = bound.as_mut() else { return };
        if !bound.checks_enabled || bound.in_flight {
            return;
        }
        let now = unix_now();
        if let Some(binary) = crate::codex_integration::codex_binary(&bound.paths)
            && let Some(verdict) = load_verdict(&bound.paths.run_dir)
            && verdict_covers(&verdict, version, &binary)
        {
            return; // already judged, either way
        }
        if bound
            .attempts
            .get(version)
            .is_some_and(|at| now.saturating_sub(*at) < RECHECK_BACKOFF.as_secs())
        {
            return;
        }
        bound.attempts.insert(version.to_owned(), now);
        bound.in_flight = true;
        (bound.paths.clone(), version.to_owned())
    };
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        clear_in_flight();
        return;
    };
    handle.spawn(async move {
        let outcome = verify_now(&paths, &version).await;
        clear_in_flight();
        match outcome {
            Ok(true) => tracing::info!(%version, "codex verified compatible; evidence carried"),
            Ok(false) => tracing::info!(%version, "codex schema changed in the read-set; version stays refused"),
            Err(error) => tracing::debug!(%version, error = %error, "codex carry check failed"),
        }
    });
}

fn clear_in_flight() {
    let mut bound = match BOUND.lock() {
        Ok(bound) => bound,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(bound) = bound.as_mut() {
        bound.in_flight = false;
    }
}

/// The whole walk: locate, hash, extract, distill, compare, persist, tally. Returns whether
/// the evidence carried. Used directly (awaited) by the CLI install/status paths and spawned
/// by `note_sighting`.
pub(crate) async fn verify_now(paths: &crate::storage::CiaoPaths, version: &str) -> Result<bool> {
    let binary = crate::codex_integration::codex_binary(paths)
        .ok_or_else(|| anyhow!("codex binary not found"))?;
    let binary = resolve_on_path(&binary).unwrap_or(binary);
    let (size, mtime) =
        binary_stat(&binary).ok_or_else(|| anyhow!("codex binary is not statable"))?;
    let hash_target = binary.clone();
    let sha256 = tokio::task::spawn_blocking(move || -> Result<String> {
        let mut hasher = Sha256::new();
        std::io::copy(&mut std::fs::File::open(&hash_target)?, &mut hasher)?;
        Ok(hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    })
    .await
    .context("hash task")??;

    let extract = extract_installed(&binary, version).await?;
    let embedded = embedded_extract().ok_or_else(|| anyhow!("embedded pin extract unreadable"))?;
    let changed: Vec<String> = embedded
        .read_set_changes(&extract)
        .into_iter()
        .map(str::to_owned)
        .collect();
    let carried = changed.is_empty();
    for name in &changed {
        crate::drift::note(
            "codex",
            "schema_extract",
            "changed_list",
            name,
            Some(version),
        );
    }
    store_verdict(
        &paths.run_dir,
        &CarryVerdict {
            v: VERDICT_FILE_VERSION,
            version: version.to_owned(),
            binary: BinaryIdentity {
                path: binary.to_string_lossy().into_owned(),
                size,
                mtime,
                sha256,
            },
            carried,
            changed,
            schema_digest: extract.schema_digest,
            checked_at: unix_now(),
        },
    );
    Ok(carried)
}

/// Cached verdict first, fresh verification second — for the interactive CLI paths where a
/// person is waiting and a subprocess run is cheaper than a wrong refusal. `Ok(true)` admits;
/// `Ok(false)` means the version is not carry-eligible or its read-set genuinely changed;
/// `Err` means the check itself could not run.
pub(crate) async fn admit_interactively(
    paths: &crate::storage::CiaoPaths,
    version: &str,
) -> Result<bool> {
    let binary = crate::codex_integration::codex_binary(paths);
    if state_for(version, &paths.run_dir, binary.as_deref()) == VendorVersionState::Carried {
        return Ok(true);
    }
    if !carry_eligible(version) {
        return Ok(false);
    }
    verify_now(paths, version).await
}

/// `codex_binary` may answer the bare name `codex` when PATH resolution worked; the verdict
/// cache needs the real file to stat and hash, so walk PATH the way the shell would.
fn resolve_on_path(binary: &Path) -> Option<PathBuf> {
    if binary.is_absolute() {
        return Some(binary.to_owned());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(binary))
        .find(|candidate| candidate.is_file())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors generated by node running the `.mjs`'s own `canonical()` verbatim, so the two
    /// implementations are pinned against each other without node in the loop.
    #[test]
    fn canonical_matches_node_byte_for_byte() {
        let cases: [(Value, &str); 4] = [
            (
                serde_json::json!({"b": 1, "a": [1.5, 1.0, -0.0, 0.0001, true, null]}),
                r#"{"a":[1.5,1,0,0.0001,true,null],"b":1}"#,
            ),
            (
                serde_json::json!({"key\u{1}ctrl\u{1f}": "line\nbreak\ttab\u{1}us \"q\" \\ back \u{8}\u{c}"}),
                "{\"key\\u0001ctrl\\u001f\":\"line\\nbreak\\ttab\\u0001us \\\"q\\\" \\\\ back \\b\\f\"}",
            ),
            (
                serde_json::json!({"unicode": "héllo → 世界", "num": 1e21, "small": 5e-7}),
                r#"{"num":1e+21,"small":5e-7,"unicode":"héllo → 世界"}"#,
            ),
            (
                serde_json::json!({"nested": {"z": {"y": [{"c": 3, "b": 2}]}}}),
                r#"{"nested":{"z":{"y":[{"b":2,"c":3}]}}}"#,
            ),
        ];
        for (value, expected) in cases {
            let mut out = String::new();
            canonical(&value, &mut out);
            assert_eq!(out, expected);
        }
    }

    /// A synthetic three-file corpus proving list extraction, `$ref` resolution, fixed-list
    /// ordering, and the digest walk — without a binary anywhere near the test.
    #[test]
    fn distillation_reads_the_shapes_the_generator_reads() {
        let directory = tempfile::tempdir().unwrap();
        let write = |name: &str, value: Value| {
            std::fs::write(
                directory.path().join(name),
                serde_json::to_vec(&value).unwrap(),
            )
            .unwrap();
        };
        write(
            "ClientRequest.json",
            serde_json::json!({
                "oneOf": [
                    {"properties": {"method": {"const": "thread/list"}, "params": {}}},
                    {"properties": {"method": {"enum": ["thread/read"]}, "params": {}}},
                    {"properties": {"method": {"const": "turn/steer"},
                        "params": {"$ref": "#/definitions/SteerParams"}}},
                    {"properties": {"method": {"const": "thread/start"},
                        "params": {"properties": {"sandbox": {"$ref": "#/definitions/SandboxMode"}}}}},
                    {"properties": {"method": {"const": "zebra/method"}, "params": {}}},
                ],
                "definitions": {
                    "SteerParams": {"required": ["threadId", "input", "expectedTurnId"]},
                    "SandboxMode": {"enum": ["read-only", "danger-full-access"]},
                }
            }),
        );
        write(
            "ServerNotification.json",
            serde_json::json!({
                "oneOf": [
                    {"properties": {"method": {"const": "turn/started"}}},
                    {"properties": {"method": {"const": "item/started"}}},
                ],
                "definitions": {
                    "HookEventName": {"enum": ["postToolUse", "sessionStart"]},
                    "HookSource": {"enum": ["userConfig"]},
                    "HookRunStatus": {"enum": ["completed"]},
                    "ThreadItem": {"oneOf": [
                        {"properties": {"type": {"const": "agentMessage"}}},
                        {"properties": {"type": {"const": "userMessage"}}},
                    ]},
                    "ThreadStatus": {"anyOf": [{"properties": {"type": {"const": "idle"}}}]},
                    "TurnStatus": {"enum": ["completed", "inProgress"]},
                    "ThreadActiveFlag": {"enum": ["waitingOnApproval"]},
                }
            }),
        );
        write("ServerRequest.json", serde_json::json!({"oneOf": []}));
        write(
            "CommandExecutionRequestApprovalResponse.json",
            serde_json::json!({"definitions": {"CommandExecutionApprovalDecision": {
                "oneOf": [{"enum": ["accept"]}, {"const": "cancel"}]}}}),
        );
        write(
            "FileChangeRequestApprovalResponse.json",
            serde_json::json!({"definitions": {"FileChangeApprovalDecision": {
                "oneOf": [{"const": "accept"}]}}}),
        );

        let extract = distill_schema_dir(directory.path()).unwrap();
        assert_eq!(extract.counts.client_methods, 5);
        assert_eq!(extract.counts.server_notifications, 2);
        assert_eq!(
            extract.required_client_methods,
            vec!["thread/read", "thread/list", "turn/steer"],
            "fixed-list order is preserved, availability filters"
        );
        assert_eq!(
            extract.steer_required_params,
            vec!["expectedTurnId", "input", "threadId"],
            "required params resolve through $ref and sort"
        );
        assert_eq!(
            extract.adopted_notifications,
            vec!["turn/started", "item/started"]
        );
        assert_eq!(
            extract.command_execution_decisions,
            vec!["accept", "cancel"]
        );
        assert!(extract.thread_start_sandbox_is_mode);
        assert_eq!(
            extract.thread_item_types,
            vec!["agentMessage", "userMessage"]
        );
        assert_eq!(extract.thread_status_types, vec!["idle"]);
        assert_eq!(extract.schema_digest.len(), 64);

        // The digest is a function of content, not of directory iteration order or mood.
        assert_eq!(
            extract.schema_digest,
            distill_schema_dir(directory.path()).unwrap().schema_digest
        );
    }

    #[test]
    fn the_embedded_extract_parses_and_matches_itself() {
        let embedded = embedded_extract().expect("embedded pins parse");
        assert_eq!(embedded.counts.client_methods, 95);
        assert!(embedded.thread_item_types.contains(&"agentMessage".into()));
        assert!(embedded.read_set_changes(embedded).is_empty());

        let mut moved = embedded.clone();
        moved.thread_item_types.push("itemFromTheFuture".into());
        moved.counts.client_methods += 1;
        moved.schema_digest = "0".repeat(64);
        assert_eq!(
            embedded.read_set_changes(&moved),
            vec!["threadItemTypes"],
            "counts and the whole-protocol digest are advisory, not read-set"
        );
    }

    #[test]
    fn a_verdict_covers_only_the_exact_binary_it_judged() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("codex");
        std::fs::write(&binary, b"synthetic codex").unwrap();
        let (size, mtime) = binary_stat(&binary).unwrap();
        let verdict = CarryVerdict {
            v: VERDICT_FILE_VERSION,
            version: "0.148.0".into(),
            binary: BinaryIdentity {
                path: binary.to_string_lossy().into_owned(),
                size,
                mtime,
                sha256: "feed".repeat(16),
            },
            carried: true,
            changed: Vec::new(),
            schema_digest: "ab".repeat(32),
            checked_at: 1,
        };
        store_verdict(directory.path(), &verdict);
        assert_eq!(load_verdict(directory.path()), Some(verdict.clone()));
        assert!(verdict_covers(&verdict, "0.148.0", &binary));
        assert!(
            !verdict_covers(&verdict, "0.149.0", &binary),
            "another version"
        );

        assert_eq!(
            state_for("0.148.0", directory.path(), Some(&binary)),
            VendorVersionState::Carried
        );
        assert_eq!(
            state_for("1.0.0", directory.path(), Some(&binary)),
            VendorVersionState::Unsupported,
            "a major is never carried"
        );
        assert_eq!(
            state_for(
                crate::codex_adapter::PINNED_CODEX_VERSION,
                directory.path(),
                Some(&binary)
            ),
            VendorVersionState::Grounded,
            "the classifier answers first"
        );

        // The binary moves under the verdict: stat misses, the carry lapses, nothing is
        // admitted on stale evidence.
        std::fs::write(&binary, b"synthetic codex, replaced").unwrap();
        assert!(!verdict_covers(&verdict, "0.148.0", &binary));
        assert_eq!(
            state_for("0.148.0", directory.path(), Some(&binary)),
            VendorVersionState::Unsupported
        );

        std::fs::write(directory.path().join(VERDICT_FILE_NAME), b"not json").unwrap();
        assert_eq!(
            load_verdict(directory.path()),
            None,
            "corrupt reads as absent"
        );
    }

    /// The whole pipeline against the real binary: locate, hash, extract, distill, compare,
    /// persist — the walk a first contact runs, here at the pinned version where the verdict
    /// must be "carried, nothing changed". Opt-in with the rest of the real-binary suite.
    #[tokio::test]
    async fn verify_now_walks_the_whole_pipeline_against_the_real_binary() {
        if std::env::var_os("CIAO_TEST_CODEX_CLI").is_none() {
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let paths = crate::storage::CiaoPaths::for_home(home.path());
        std::fs::create_dir_all(&paths.run_dir).unwrap();
        let carried = verify_now(&paths, crate::codex_adapter::PINNED_CODEX_VERSION)
            .await
            .expect("the walk runs");
        assert!(carried, "the pinned binary matches its own extract");
        let verdict = load_verdict(&paths.run_dir).expect("the verdict persisted");
        assert!(verdict.carried);
        assert!(verdict.changed.is_empty());
        assert_eq!(verdict.binary.sha256.len(), 64);
        assert!(
            Path::new(&verdict.binary.path).is_absolute(),
            "the verdict records the resolved file, not the bare PATH name"
        );
    }

    /// The lock (Spec 017 §4.3): against the real pinned binary, this port reproduces the
    /// `.mjs`'s distillation byte for byte — digest, counts, and every list. Opt-in like every
    /// test that spawns a real `codex`, and skipped silently elsewhere.
    #[tokio::test]
    async fn the_rust_distiller_reproduces_the_pinned_extract_against_the_real_binary() {
        if std::env::var_os("CIAO_TEST_CODEX_CLI").is_none() {
            return;
        }
        let binary = resolve_on_path(Path::new("codex")).expect("codex on PATH");
        let extract = extract_installed(&binary, crate::codex_adapter::PINNED_CODEX_VERSION)
            .await
            .expect("extraction against the pinned binary");
        let embedded = embedded_extract().expect("embedded pins parse");
        assert_eq!(
            extract.schema_digest, embedded.schema_digest,
            "the canonicalizer and digest walk must match node exactly"
        );
        assert_eq!(
            &extract, embedded,
            "every distilled field matches the pins file"
        );
    }
}
