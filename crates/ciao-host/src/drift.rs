//! The drift ledger: what vendors sent that this build did not recognize. Spec 017 §4.2.
//!
//! Every vendor parser in this crate already degrades gracefully — unknown frames become
//! unsupported cards, unknown transcript entries are skipped, malformed mux lines are omitted
//! and counted. What none of them did was leave a record, so four silent swallows in a row
//! looked identical to a quiet vendor. This module is the record: one bounded, deduplicated
//! tally of the *shapes* tolerance absorbed, per vendor, kept where the person debugging a
//! degradation can read it (`ciao drift`) and where a release can be cut against it.
//!
//! A note is a signature — an event type, a method name, an enum token — and **names, never
//! values**. The conformance ledgers' rule applies verbatim: no prompt text, no paths, no
//! payloads, nothing a person typed. A name that does not look like vendor vocabulary is
//! recorded as `invalid` rather than trusted.
//!
//! One process-wide sink, callable from any depth without threading a handle through pure
//! parsers. The daemon binds it to `run/drift-ledger.json` at startup; unbound processes (the
//! CLI, one-shot hook deliveries) can note freely and the tally simply dies with them — hook
//! processes report novelty to the daemon in their frames instead, and the daemon notes it
//! here on decode.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

pub(crate) const LEDGER_FILE_NAME: &str = "drift-ledger.json";
const LEDGER_FILE_VERSION: u8 = 1;
/// Distinct signatures kept per vendor. Real drift is a handful of new shapes per vendor
/// release; a vendor producing more than this is misbehaving, and the overflow counter says so
/// without letting it grow the file.
const MAX_SIGNATURES_PER_VENDOR: usize = 64;
/// Vendor vocabulary is short. Anything longer is not a name Ciao should repeat.
const MAX_NAME_BYTES: usize = 48;
const MAX_LEDGER_BYTES: usize = 64 * 1024;
/// Count-only updates are flushed lazily; a new signature is flushed immediately, because the
/// first sighting is the information and a count is only its weight.
const FLUSH_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DriftLedger {
    pub(crate) v: u8,
    /// BTreeMap so two writes of the same state are byte-identical.
    pub(crate) vendors: BTreeMap<String, VendorDrift>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VendorDrift {
    pub(crate) signatures: Vec<DriftSignature>,
    /// Distinct signatures seen past the cap. Counted so a truncated ledger never reads as a
    /// complete one — the no-silent-caps rule from the spec.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) overflow: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DriftSignature {
    /// Which reader saw it: `hook_event`, `bridge_frame`, `adopted_notification`, `history_item`,
    /// `transcript`, `mux_list`, `sdk_stream`. A closed set named at the call sites.
    pub(crate) surface: String,
    /// What was unrecognized about it: `unknown_event`, `unknown_method`, `unknown_item`,
    /// `unknown_enum`, `invalid`, `omitted`.
    pub(crate) kind: String,
    /// The vendor's own word for the thing, sanitized. Empty for pure counters (an omitted mux
    /// line has no name worth repeating).
    pub(crate) name: String,
    pub(crate) count: u64,
    pub(crate) first_seen: u64,
    pub(crate) last_seen: u64,
    /// The vendor version sighted when this was last observed, when the call site knows one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) seen_at_version: Option<String>,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl DriftLedger {
    fn empty() -> Self {
        Self {
            v: LEDGER_FILE_VERSION,
            vendors: BTreeMap::new(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.vendors
            .values()
            .all(|vendor| vendor.signatures.is_empty() && vendor.overflow == 0)
    }

    /// Total distinct signatures for one vendor, overflow included — the number status lines
    /// print as "kinds of input".
    pub(crate) fn distinct_for(&self, vendor: &str) -> u64 {
        self.vendors
            .get(vendor)
            .map(|entry| entry.signatures.len() as u64 + entry.overflow)
            .unwrap_or(0)
    }
}

struct Sink {
    ledger: DriftLedger,
    path: Option<PathBuf>,
    dirty: bool,
    last_flush: u64,
}

static SINK: LazyLock<Mutex<Sink>> = LazyLock::new(|| {
    Mutex::new(Sink {
        ledger: DriftLedger::empty(),
        path: None,
        dirty: false,
        last_flush: 0,
    })
});

/// Records one unrecognized shape. Callable from anywhere in the process; cheap enough for a
/// per-line parser, since a repeat signature is one map probe and a counter.
pub(crate) fn note(vendor: &str, surface: &str, kind: &str, name: &str, version: Option<&str>) {
    note_by(vendor, surface, kind, name, version, 1);
}

/// `note`, weighted — for call sites that already counted (a mux listing that omitted N lines
/// reports once with N, not N times).
pub(crate) fn note_by(
    vendor: &str,
    surface: &str,
    kind: &str,
    name: &str,
    version: Option<&str>,
    occurrences: u64,
) {
    if occurrences == 0 {
        return;
    }
    let now = unix_now();
    let name = sanitize_name(name);
    let mut sink = match SINK.lock() {
        Ok(sink) => sink,
        // A poisoned tally is not worth a panic anywhere near a parser.
        Err(poisoned) => poisoned.into_inner(),
    };
    let vendor_entry = sink
        .ledger
        .vendors
        .entry(sanitize_name(vendor))
        .or_default();
    let mut new_signature = false;
    if let Some(signature) = vendor_entry.signatures.iter_mut().find(|existing| {
        existing.surface == surface && existing.kind == kind && existing.name == name
    }) {
        signature.count = signature.count.saturating_add(occurrences);
        signature.last_seen = now;
        if version.is_some() {
            signature.seen_at_version = version.map(str::to_owned);
        }
    } else if vendor_entry.signatures.len() >= MAX_SIGNATURES_PER_VENDOR {
        vendor_entry.overflow = vendor_entry.overflow.saturating_add(1);
    } else {
        vendor_entry.signatures.push(DriftSignature {
            surface: sanitize_name(surface),
            kind: sanitize_name(kind),
            name,
            count: occurrences,
            first_seen: now,
            last_seen: now,
            seen_at_version: version.map(str::to_owned),
        });
        new_signature = true;
    }
    sink.dirty = true;
    if new_signature || now.saturating_sub(sink.last_flush) >= FLUSH_INTERVAL_SECS {
        flush_locked(&mut sink, now);
    }
}

/// Points the sink at its file and loads whatever a previous run left there. Daemon startup
/// only; everything before the bind stays in memory and is carried into the loaded ledger.
pub(crate) fn bind(run_dir: &Path) {
    let path = run_dir.join(LEDGER_FILE_NAME);
    let loaded = load(&path).unwrap_or_else(DriftLedger::empty);
    let now = unix_now();
    let mut sink = match SINK.lock() {
        Ok(sink) => sink,
        Err(poisoned) => poisoned.into_inner(),
    };
    let unpersisted = std::mem::replace(&mut sink.ledger, loaded);
    for (vendor, entry) in unpersisted.vendors {
        for signature in entry.signatures {
            let target = sink.ledger.vendors.entry(vendor.clone()).or_default();
            merge_signature(target, signature);
        }
    }
    sink.path = Some(path);
    if sink.dirty {
        flush_locked(&mut sink, now);
    }
}

fn merge_signature(vendor: &mut VendorDrift, incoming: DriftSignature) {
    if let Some(existing) = vendor.signatures.iter_mut().find(|existing| {
        existing.surface == incoming.surface
            && existing.kind == incoming.kind
            && existing.name == incoming.name
    }) {
        existing.count = existing.count.saturating_add(incoming.count);
        existing.last_seen = existing.last_seen.max(incoming.last_seen);
        if incoming.seen_at_version.is_some() {
            existing.seen_at_version = incoming.seen_at_version;
        }
    } else if vendor.signatures.len() >= MAX_SIGNATURES_PER_VENDOR {
        vendor.overflow = vendor.overflow.saturating_add(1);
    } else {
        vendor.signatures.push(incoming);
    }
}

/// Writes pending notes out now. Daemon shutdown; harmless when unbound or clean.
pub(crate) fn flush() {
    let mut sink = match SINK.lock() {
        Ok(sink) => sink,
        Err(poisoned) => poisoned.into_inner(),
    };
    if sink.dirty {
        let now = unix_now();
        flush_locked(&mut sink, now);
    }
}

fn flush_locked(sink: &mut Sink, now: u64) {
    let Some(path) = sink.path.clone() else {
        return;
    };
    let bytes = match serde_json::to_vec(&sink.ledger) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };
    // Cannot happen under the per-vendor caps unless vendor *count* runs away; refusing the
    // write keeps the bound honest either way.
    if bytes.len() > MAX_LEDGER_BYTES {
        tracing::debug!("drift ledger exceeded its size bound; not persisted");
        return;
    }
    match crate::storage::atomic_write_private(&path, &bytes) {
        Ok(()) => {
            sink.dirty = false;
            sink.last_flush = now;
        }
        Err(error) => {
            tracing::debug!(error = %error, "drift ledger write failed");
        }
    }
}

/// Reads a persisted ledger. Tolerant the way every vendor reader here is: a missing, oversized,
/// malformed, or wrong-version file is `None`, never an error — the ledger is diagnostics, and
/// diagnostics must not be able to break the thing they describe.
pub(crate) fn load(path: &Path) -> Option<DriftLedger> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > MAX_LEDGER_BYTES as u64 {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let ledger: DriftLedger = serde_json::from_slice(&bytes).ok()?;
    (ledger.v == LEDGER_FILE_VERSION).then_some(ledger)
}

/// What an absent or unreadable ledger means: nothing recorded.
pub(crate) fn empty_ledger() -> DriftLedger {
    DriftLedger::empty()
}

/// Live distinct-signature count for one vendor, read from the in-process tally — the number a
/// drift note carries as `gaps`. Zero when nothing was ever noted, which is the good news.
pub(crate) fn live_distinct_for(vendor: &str) -> u64 {
    match SINK.lock() {
        Ok(sink) => sink.ledger.distinct_for(vendor),
        Err(poisoned) => poisoned.into_inner().ledger.distinct_for(vendor),
    }
}

/// A copy of the live tally, for tests and for a bound process reading its own state.
#[cfg(test)]
pub(crate) fn snapshot() -> DriftLedger {
    match SINK.lock() {
        Ok(sink) => sink.ledger.clone(),
        Err(poisoned) => poisoned.into_inner().ledger.clone(),
    }
}

/// Vendor vocabulary only: method names, event types, enum tokens. Anything outside that
/// grammar — or overlong — is recorded as the word `invalid`, because a name that cannot be
/// trusted as a name must not be stored as one.
pub(crate) fn sanitize_name(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    let token = name.len() <= MAX_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'));
    if token {
        name.to_owned()
    } else {
        "invalid".into()
    }
}

/// The `ciao drift` text rendering. Plain words, newest-relevant facts only; the JSON form is
/// the file itself.
pub(crate) fn render(ledger: &DriftLedger) -> String {
    if ledger.is_empty() {
        return "No vendor drift recorded. Everything the installed agents sent was recognized."
            .into();
    }
    let mut out = String::new();
    for (vendor, entry) in &ledger.vendors {
        if entry.signatures.is_empty() && entry.overflow == 0 {
            continue;
        }
        out.push_str(&format!(
            "{vendor}: {} kinds of input this build does not recognize\n",
            entry.signatures.len() as u64 + entry.overflow
        ));
        for signature in &entry.signatures {
            let name = if signature.name.is_empty() {
                String::new()
            } else {
                format!(" {}", signature.name)
            };
            let version = signature
                .seen_at_version
                .as_deref()
                .map(|version| format!(" (vendor {version})"))
                .unwrap_or_default();
            out.push_str(&format!(
                "  {} {}{name}: seen {}x{version}\n",
                signature.surface, signature.kind, signature.count
            ));
        }
        if entry.overflow > 0 {
            out.push_str(&format!(
                "  and {} more kinds past the ledger's cap\n",
                entry.overflow
            ));
        }
    }
    out.push_str("Names only, never content. A Ciao release is cut against this list.");
    out
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

    // The sink is process-wide and tests share the process, so every test uses vendor names no
    // other test touches and asserts only within them.

    #[test]
    fn notes_deduplicate_count_and_bound() {
        for round in 0..2 {
            for shape in 0..70 {
                note(
                    "testvendor-bounds",
                    "hook_event",
                    "unknown_event",
                    &format!("Shape{shape}"),
                    Some("9.9.9"),
                );
                let _ = round;
            }
        }
        let ledger = snapshot();
        let vendor = &ledger.vendors["testvendor-bounds"];
        assert_eq!(vendor.signatures.len(), MAX_SIGNATURES_PER_VENDOR);
        // Second round repeats the first 64 (counted) and re-overflows the last 6.
        assert_eq!(vendor.overflow, 12);
        let first = vendor
            .signatures
            .iter()
            .find(|signature| signature.name == "Shape0")
            .unwrap();
        assert_eq!(first.count, 2);
        assert_eq!(first.seen_at_version.as_deref(), Some("9.9.9"));
        assert_eq!(ledger.distinct_for("testvendor-bounds"), 76);
    }

    #[test]
    fn names_outside_vendor_vocabulary_are_never_stored() {
        note(
            "testvendor-sanitize",
            "transcript",
            "unknown_enum",
            "user typed this\nwhole thing",
            None,
        );
        note(
            "testvendor-sanitize",
            "transcript",
            "unknown_enum",
            &"x".repeat(200),
            None,
        );
        let ledger = snapshot();
        let vendor = &ledger.vendors["testvendor-sanitize"];
        assert_eq!(vendor.signatures.len(), 1, "both collapse onto `invalid`");
        assert_eq!(vendor.signatures[0].name, "invalid");
        assert_eq!(vendor.signatures[0].count, 2);
    }

    #[test]
    fn a_persisted_ledger_survives_a_reload_and_garbage_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LEDGER_FILE_NAME);
        let mut ledger = DriftLedger::empty();
        let mut vendor = VendorDrift::default();
        vendor.signatures.push(DriftSignature {
            surface: "adopted_notification".into(),
            kind: "unknown_method".into(),
            name: "threadSection/created".into(),
            count: 3,
            first_seen: 1,
            last_seen: 2,
            seen_at_version: Some("0.148.0".into()),
        });
        ledger.vendors.insert("testvendor-roundtrip".into(), vendor);
        crate::storage::atomic_write_private(&path, &serde_json::to_vec(&ledger).unwrap()).unwrap();
        assert_eq!(load(&path), Some(ledger));

        std::fs::write(&path, b"not json at all").unwrap();
        assert_eq!(load(&path), None, "a corrupt ledger is absent, not fatal");
        std::fs::write(&path, br#"{"v":9,"vendors":{}}"#).unwrap();
        assert_eq!(
            load(&path),
            None,
            "an unknown version is absent, not trusted"
        );
    }

    #[test]
    fn rendering_is_plain_and_says_when_there_is_nothing() {
        let empty = DriftLedger::empty();
        assert!(render(&empty).starts_with("No vendor drift recorded"));

        let mut ledger = DriftLedger::empty();
        let mut vendor = VendorDrift::default();
        vendor.signatures.push(DriftSignature {
            surface: "hook_event".into(),
            kind: "unknown_event".into(),
            name: "FutureEvent".into(),
            count: 4,
            first_seen: 1,
            last_seen: 2,
            seen_at_version: Some("2.2.0".into()),
        });
        vendor.overflow = 2;
        ledger.vendors.insert("claude".into(), vendor);
        let text = render(&ledger);
        assert!(text.contains("claude: 3 kinds of input"));
        assert!(text.contains("hook_event unknown_event FutureEvent: seen 4x (vendor 2.2.0)"));
        assert!(text.contains("and 2 more kinds past the ledger's cap"));
        assert!(!text.contains('\u{2014}'), "no em dashes in visible copy");
    }
}
