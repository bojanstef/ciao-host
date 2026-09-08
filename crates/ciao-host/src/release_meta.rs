//! The promise that keeps itself (Spec 017 §4.4, Phase 4).
//!
//! Ciao cannot promise a future release fixes anything; it can know whether a **shipped** one
//! does. Each release publishes `meta.json` beside the artifact manifest — `{v, host, vendors:
//! {name: {rule, pinned}}}`, emitted by `package_host.py` from the same Rust constants the
//! daemon enforces. A drifting host polls it and answers one question per sighted vendor: does
//! a released Ciao already ground the version this machine is seeing? Yes → the drift note
//! gains `fix: "0.1.X"` and the phone's line flips from "a Ciao update will cover them" to
//! "Fixed in Ciao 0.1.X. Update Ciao on that host to pick it up." — by itself, before the user
//! does anything.
//!
//! No drift, no poll, no beacon: the fetch happens only while some sighted vendor is past this
//! build's grounding and unanswered, at most daily with per-process jitter, silently on
//! failure, against the same origin the daemon already POSTs notifications to, carrying no
//! identifiers. `CIAO_DISABLE_RELEASE_POLL=1` turns it off entirely. The last answer persists
//! in `run/release-meta.json`, so a restart does not re-ask a question it already had answered.

use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::{LazyLock, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;

use crate::agent_protocol::{VendorVersionState, classify_vendor_version};

/// The local cache of the last fetched meta — also the curl destination.
pub(crate) const META_CACHE_FILE: &str = "release-meta.json";
const REMOTE_META_FILE: &str = "meta.json";
const MAX_META_BYTES: u64 = 16 * 1024;
/// The poll floor; a per-process jitter of up to eight hours rides on top, so a fleet of
/// drifting hosts does not ask in step.
const POLL_FLOOR_SECS: u64 = 20 * 60 * 60;
const POLL_JITTER_SECS: u64 = 8 * 60 * 60;
/// How often the loop re-examines whether a poll is due. Cheap: a mutex and two clocks.
pub(crate) const POLL_TICK_SECS: u64 = 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct MetaVendor {
    pub(crate) pinned: String,
    // `rule` is carried in the file for the human reading it; the daemon applies its own
    // classifier and ignores fields it does not know — this parser is as tolerant as the one
    // Spec 017 loosened, for the same reason.
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct ReleaseMeta {
    pub(crate) v: u8,
    pub(crate) host: String,
    #[serde(default)]
    pub(crate) vendors: BTreeMap<String, MetaVendor>,
}

/// Tolerant parse: wrong version, oversize, malformed, or hostile shapes read as no meta at
/// all. The file is a promise, and a promise that cannot be read is simply not made.
pub(crate) fn parse_meta(bytes: &[u8]) -> Option<ReleaseMeta> {
    if bytes.len() as u64 > MAX_META_BYTES {
        return None;
    }
    let meta: ReleaseMeta = serde_json::from_slice(bytes).ok()?;
    if meta.v != 1
        || meta.host.is_empty()
        || meta.host.len() > 64
        || crate::agent_protocol::parse_version(&meta.host).is_none()
        || meta.vendors.len() > 16
    {
        return None;
    }
    meta.vendors
        .values()
        .all(|vendor| !vendor.pinned.is_empty() && vendor.pinned.len() <= 64)
        .then_some(meta)
}

/// Whether the release described by `meta` *grounds* this sighted version — not merely admits
/// it. `Grounded` is the only honest meaning of "fixed": a version the newer release would
/// still be running ahead of, or still refusing, is not fixed by updating.
pub(crate) fn covers(meta: &ReleaseMeta, vendor: &str, version: &str) -> bool {
    meta.vendors.get(vendor).is_some_and(|entry| {
        classify_vendor_version(version, &entry.pinned) == VendorVersionState::Grounded
    })
}

// ---------------------------------------------------------------------------
// Sightings and resolved fixes, process-wide like the drift ledger.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Sighting {
    version: String,
    /// Past this build's grounding in the direction an update could fix: `ahead`, or
    /// `unsupported` with a version newer than the tested pin. Below-floor and stale
    /// sightings are not drift — updating Ciao does not fix an old vendor.
    drifting: bool,
}

struct State {
    sightings: HashMap<String, Sighting>,
    fixes: HashMap<String, String>,
    meta: Option<ReleaseMeta>,
    last_poll: u64,
    jitter: u64,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| {
    Mutex::new(State {
        sightings: HashMap::new(),
        fixes: HashMap::new(),
        meta: None,
        last_poll: 0,
        jitter: rand::random::<u64>() % POLL_JITTER_SECS,
    })
});

fn lock() -> std::sync::MutexGuard<'static, State> {
    match STATE.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Records what a registration saw, and resolves it against whatever meta is already held.
/// Called from the session layer's drift-note construction, which runs on every registration,
/// so sightings stay current without their own plumbing.
pub(crate) fn sighted(vendor: &str, version: &str, state_token: &str, tested: &str) {
    let newer = match (
        crate::agent_protocol::parse_version(version),
        crate::agent_protocol::parse_version(tested),
    ) {
        (Some(running), Some(tested)) => running > tested,
        _ => false,
    };
    let drifting = state_token == "ahead" || (state_token == "unsupported" && newer);
    let mut state = lock();
    state.sightings.insert(
        vendor.to_owned(),
        Sighting {
            version: version.to_owned(),
            drifting,
        },
    );
    resolve_locked(&mut state);
}

/// The released Ciao version that grounds this vendor's sighted version, once known.
pub(crate) fn fix_for(vendor: &str) -> Option<String> {
    lock().fixes.get(vendor).cloned()
}

/// Installs a fetched (or cached) meta and re-resolves every sighting against it.
pub(crate) fn apply_meta(meta: ReleaseMeta) {
    let mut state = lock();
    state.meta = Some(meta);
    resolve_locked(&mut state);
}

fn resolve_locked(state: &mut State) {
    let Some(meta) = state.meta.clone() else {
        return;
    };
    // A fix, once made, is only ever restated or improved by a newer meta — recompute from
    // scratch so a stale answer for a vendor that moved again does not linger.
    state.fixes.clear();
    for (vendor, sighting) in &state.sightings {
        if sighting.drifting && covers(&meta, vendor, &sighting.version) {
            state.fixes.insert(vendor.clone(), meta.host.clone());
        }
    }
}

/// Loads the last fetched meta at daemon start, so an answer already given survives restarts
/// without a fetch.
pub(crate) fn load_cached(run_dir: &Path) {
    let path = run_dir.join(META_CACHE_FILE);
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    if let Some(meta) = parse_meta(&bytes) {
        apply_meta(meta);
    }
}

/// Whether a fetch is due right now: something drifting is still unanswered, the backoff has
/// elapsed, and nobody switched the poll off.
fn poll_due(now: u64) -> bool {
    if std::env::var_os("CIAO_DISABLE_RELEASE_POLL").is_some_and(|value| !value.is_empty()) {
        return false;
    }
    let state = lock();
    let unanswered = state
        .sightings
        .iter()
        .any(|(vendor, sighting)| sighting.drifting && !state.fixes.contains_key(vendor));
    unanswered && now.saturating_sub(state.last_poll) >= POLL_FLOOR_SECS + state.jitter
}

/// The daemon's poll loop: one hourly tick, one bounded fetch when due, silence otherwise.
pub(crate) async fn poll_loop(paths: crate::storage::CiaoPaths, release_base: String) {
    load_cached(&paths.run_dir);
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(POLL_TICK_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let now = unix_now();
        if !poll_due(now) {
            continue;
        }
        lock().last_poll = now;
        let dest = paths.run_dir.join(META_CACHE_FILE);
        let base = release_base.clone();
        let fetched = tokio::task::spawn_blocking(move || {
            crate::install::fetch_release_file(&base, REMOTE_META_FILE, &dest, None)
        })
        .await;
        match fetched {
            Ok(Ok(())) => {
                let bytes = std::fs::read(paths.run_dir.join(META_CACHE_FILE)).unwrap_or_default();
                match parse_meta(&bytes) {
                    Some(meta) => {
                        let host = meta.host.clone();
                        apply_meta(meta);
                        tracing::info!(release = %host, "release meta fetched while drifting");
                    }
                    None => tracing::debug!("release meta was unreadable; ignored"),
                }
            }
            Ok(Err(error)) => tracing::debug!(error = %error, "release meta fetch failed"),
            Err(error) => tracing::debug!(error = %error, "release meta fetch task failed"),
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Serializes every test that touches the process-wide meta, across modules — `apply_meta`
/// deliberately replaces the one held meta, so unsynchronized tests would clear each other's
/// resolutions mid-assert.
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    match TEST_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The state is process-wide and `apply_meta` deliberately *replaces* the held meta — in
    // production there is exactly one release channel. Tests that touch the global (here and
    // in other modules) serialize on `super::test_lock()` and use vendor names nothing else
    // touches.

    fn meta(host: &str, vendor: &str, pinned: &str) -> ReleaseMeta {
        parse_meta(
            serde_json::json!({
                "v": 1,
                "host": host,
                "vendors": { vendor: { "rule": "minor_floor", "pinned": pinned } },
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn meta_parsing_is_tolerant_of_growth_and_refuses_garbage() {
        let grown = serde_json::json!({
            "v": 1,
            "host": "0.1.40",
            "generated_by": "a future field",
            "vendors": {
                "codex": { "rule": "minor_floor", "pinned": "0.148.0", "note": "future" },
            },
        });
        let parsed = parse_meta(grown.to_string().as_bytes()).expect("growth tolerated");
        assert_eq!(parsed.host, "0.1.40");
        assert_eq!(parsed.vendors["codex"].pinned, "0.148.0");

        assert!(parse_meta(b"not json").is_none());
        assert!(parse_meta(br#"{"v":2,"host":"0.1.40","vendors":{}}"#).is_none());
        assert!(
            parse_meta(br#"{"v":1,"host":"not-a-version","vendors":{}}"#).is_none(),
            "the promised release must itself be a version"
        );
        let oversized = format!(
            r#"{{"v":1,"host":"0.1.40","vendors":{{}},"pad":"{}"}}"#,
            "x".repeat(20_000)
        );
        assert!(parse_meta(oversized.as_bytes()).is_none());
    }

    #[test]
    fn covers_means_grounded_not_merely_admitted() {
        let released = meta("0.1.40", "claude", "2.2.5");
        assert!(
            covers(&released, "claude", "2.2.7"),
            "a later patch of the released minor is grounded: fixed"
        );
        assert!(
            !covers(&released, "claude", "2.3.0"),
            "the release would run this ahead, which is not a fix"
        );
        assert!(
            !covers(&released, "claude", "2.2.0"),
            "below the released floor is refused there, which is not a fix either"
        );
        assert!(!covers(&released, "codex", "0.148.0"), "unknown vendor");

        let codex = meta("0.1.40", "codex", "0.148.2");
        assert!(covers(&codex, "codex", "0.148.5"));
        assert!(
            !covers(&codex, "codex", "0.149.0"),
            "a 0.x minor past the release"
        );
    }

    #[test]
    fn a_sighting_resolves_to_a_fix_only_while_drifting() {
        let _held = test_lock();
        apply_meta(meta("0.1.41", "fixture-promise", "2.2.0"));
        sighted("fixture-promise", "2.2.3", "ahead", "2.1.222");
        assert_eq!(fix_for("fixture-promise").as_deref(), Some("0.1.41"));

        // The vendor moves again past the released pin: the old answer must not linger.
        sighted("fixture-promise", "2.3.0", "ahead", "2.1.222");
        assert_eq!(fix_for("fixture-promise"), None);

        // Grounded sightings never resolve to anything: there is nothing to fix.
        sighted("fixture-promise-idle", "2.1.230", "grounded", "2.1.222");
        assert_eq!(fix_for("fixture-promise-idle"), None);
    }

    #[test]
    fn a_refused_but_newer_sighting_is_drifting_and_resolvable() {
        let _held = test_lock();
        // The codex shape: a 0.x minor the build refuses (schema changed), fixed by a release
        // whose pin grounds it.
        apply_meta(meta("0.1.42", "fixture-refused", "0.148.0"));
        sighted("fixture-refused", "0.148.1", "unsupported", "0.147.0");
        assert_eq!(fix_for("fixture-refused").as_deref(), Some("0.1.42"));

        // Below the floor is old, not drifting: updating Ciao fixes nothing about it.
        sighted("fixture-refused-old", "0.146.0", "unsupported", "0.147.0");
        apply_meta(meta("0.1.42", "fixture-refused-old", "0.148.0"));
        assert_eq!(fix_for("fixture-refused-old"), None);
    }

    #[test]
    fn cached_meta_survives_a_restart_shaped_reload() {
        let _held = test_lock();
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join(META_CACHE_FILE),
            serde_json::json!({
                "v": 1,
                "host": "0.1.43",
                "vendors": { "fixture-reload": { "rule": "minor_floor", "pinned": "3.1.0" } },
            })
            .to_string(),
        )
        .unwrap();
        load_cached(directory.path());
        sighted("fixture-reload", "3.1.4", "ahead", "3.0.0");
        assert_eq!(fix_for("fixture-reload").as_deref(), Some("0.1.43"));
    }
}
