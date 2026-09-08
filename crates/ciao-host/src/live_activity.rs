//! Spec 018 §3-§4: the one mapping from canonical session facts to Live Activity rows.
//!
//! Delivery used to reach into the Agent supervisor and the managed directory itself, which put
//! `notify.rs` above session state rather than beside it. This module is the seam that removed
//! that: the sweep snapshots both owners, projects them once into an immutable value, and hands
//! delivery something it can only read.
//!
//! Only Spec 018 §4's approved facts cross — an opaque session ID, the adapter family, the
//! workspace label, the turn-opening prompt, and a categorical state — each already cut to its
//! §8 bound here, so nothing unbounded is carried and no timeline content exists to carry.

use std::collections::{HashMap, HashSet};

use crate::{
    agent_protocol::{AgentSessionDescriptor, TurnState},
    managed_session::ManagedSessionSummary,
};

pub(crate) const MAX_LIVE_ACTIVITY_ADAPTER_CHARACTERS: usize = 32;
pub(crate) const MAX_LIVE_ACTIVITY_DISPLAY_BYTES: usize = 64;

/// Bounded labels a live session names itself by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveActivityLabels {
    pub(crate) agent: String,
    pub(crate) workspace: String,
    /// The turn-opening prompt, when the descriptor names one. The workspace alone cannot tell
    /// two agents in one directory apart — the same reasoning as `recent_prompt` on the
    /// descriptor, carried to the Lock Screen.
    pub(crate) prompt: Option<String>,
}

/// What one session's owners currently claim about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveActivitySessionFact {
    pub(crate) state: &'static str,
    /// Absent for a session with no live descriptor. The row then keeps the labels captured at
    /// opt-in rather than inventing new ones.
    pub(crate) labels: Option<LiveActivityLabels>,
}

/// Every claim both owners make, snapshotted at one instant.
///
/// Immutable by construction: it is built from owned snapshots, so no lock is held while delivery
/// seals, posts, or retries.
#[derive(Debug, Clone, Default)]
pub(crate) struct LiveActivityOverview {
    facts: HashMap<String, LiveActivitySessionFact>,
}

impl LiveActivityOverview {
    pub(crate) fn project(
        descriptors: Vec<AgentSessionDescriptor>,
        stored: Vec<ManagedSessionSummary>,
        ended: &HashSet<String>,
    ) -> Self {
        let mut facts = HashMap::new();
        // Observed ends first, weakest: a verdict the supervisor recorded when it watched the
        // session die or heard the vendor end it. Without one, absence stays `unknown` — a
        // daemon that restarted observed nothing and may not guess.
        for session_id in ended {
            facts.insert(
                session_id.clone(),
                LiveActivitySessionFact {
                    state: "stopped",
                    labels: None,
                },
            );
        }
        // A persisted record carries the more specific word — `failed` names a crash — so it
        // overrides a bare end verdict, and the descriptors come last and win.
        for summary in stored {
            if summary.presence != "stored" {
                continue;
            }
            facts.insert(
                summary.session_id,
                LiveActivitySessionFact {
                    state: if summary.stored_reason.as_deref() == Some("worker_crash") {
                        "failed"
                    } else {
                        "stopped"
                    },
                    labels: None,
                },
            );
        }
        for descriptor in descriptors {
            // A descriptor that only says `unknown` may not mask a concrete verdict another
            // owner holds: a downgraded row sat on top of the directory's `stopped`/`failed`
            // and turned every ended managed session into a permanent "Watching". The verdict
            // keeps the state; the descriptor still contributes the freshest labels.
            let state = match facts.get(&descriptor.session_id) {
                Some(prior) if state_for(&descriptor) == "unknown" => prior.state,
                _ => state_for(&descriptor),
            };
            facts.insert(
                descriptor.session_id.clone(),
                LiveActivitySessionFact {
                    state,
                    labels: Some(LiveActivityLabels {
                        agent: bounded_ascii_token(
                            &descriptor.adapter_family,
                            MAX_LIVE_ACTIVITY_ADAPTER_CHARACTERS,
                        ),
                        workspace: bounded_utf8(
                            &descriptor.workspace_display,
                            MAX_LIVE_ACTIVITY_DISPLAY_BYTES,
                        ),
                        prompt: descriptor
                            .recent_prompt
                            .as_deref()
                            .filter(|prompt| !prompt.is_empty())
                            .map(|prompt| bounded_utf8(prompt, MAX_LIVE_ACTIVITY_DISPLAY_BYTES)),
                    }),
                },
            );
        }
        Self { facts }
    }

    /// `None` when neither owner claims anything about this session. Absence is not proof of
    /// completion or idleness, so the caller withdraws the state claim rather than guessing one.
    pub(crate) fn fact(&self, session_id: &str) -> Option<&LiveActivitySessionFact> {
        self.facts.get(session_id)
    }
}

fn state_for(descriptor: &AgentSessionDescriptor) -> &'static str {
    if descriptor.presence == "stored" {
        return "stopped";
    }
    match &descriptor.turn {
        TurnState::AwaitingInteraction { .. } => "needs_input",
        TurnState::Failed { .. } => "failed",
        TurnState::Running { .. } if descriptor.observation.coverage == "authoritative" => {
            "working"
        }
        TurnState::Running { .. } => "active",
        TurnState::Stopping { .. } => "stopping",
        TurnState::Completed { .. } | TurnState::Interrupted { .. } => "done",
        TurnState::Idle => "idle",
        TurnState::Unknown { .. } | TurnState::Unsupported => "unknown",
    }
}

/// Spec 018 §3's order, highest attention first. It lives beside the vocabulary that produces the
/// words so a new state cannot gain a spelling without a rank.
pub(crate) fn state_priority(state: &str) -> u8 {
    match state {
        "needs_input" => 0,
        "failed" => 1,
        "working" => 2,
        "active" => 3,
        "stopping" => 4,
        "done" => 5,
        "idle" => 6,
        "stopped" => 7,
        _ => 8,
    }
}

/// Truncation is marked, not silent. A prompt cut mid-word reads as a broken string; the same cut
/// with an ellipsis reads as a long one. The marker replaces a character rather than being added
/// to the end, so the bound is still the bound.
pub(crate) fn bounded_ascii_token(value: &str, bytes: usize) -> String {
    value.bytes().take(bytes).map(char::from).collect()
}

pub(crate) fn bounded_utf8(value: &str, bytes: usize) -> String {
    if value.len() <= bytes {
        return value.to_owned();
    }
    let marker = '…';
    let content_bytes = bytes.saturating_sub(marker.len_utf8());
    let mut result = String::new();
    for character in value.chars() {
        if result.len().saturating_add(character.len_utf8()) > content_bytes {
            break;
        }
        result.push(character);
    }
    result.push(marker);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec 018 §3: `active` is a running turn the adapter reports but cannot fully observe, and
    /// it is never relabelled Working.
    ///
    /// The two words say different things. Working means Ciao is watching the turn run; active
    /// means the adapter said so and Ciao cannot check. Collapsing them would put the stronger
    /// claim on a Lock Screen on the strength of the weaker one, which is the failure this
    /// vocabulary exists to prevent — and the reducer that decides it had no test at all.
    #[test]
    fn a_running_turn_under_partial_observation_is_active_and_never_working() {
        let base = fixture_descriptor();
        // The canonical descriptor is already the interesting case: attached, live, and partial.
        assert_eq!(base.observation.coverage, "partial");
        assert_eq!(base.presence, "live");

        let mut running = base.clone();
        running.turn = TurnState::Running {
            run_id: "run-a".into(),
            activity: "thinking".into(),
        };
        assert_eq!(state_for(&running), "active");

        // The same turn under authoritative observation is the stronger claim, and only then.
        let mut authoritative = running.clone();
        authoritative.observation.coverage = "authoritative".into();
        assert_eq!(state_for(&authoritative), "working");

        // Only that exact word grants it. A coverage value a future adapter invents, or one that
        // differs by case or whitespace, degrades to the weaker claim rather than being waved
        // through as the stronger one.
        for coverage in ["", "unknown", "none", "Authoritative", "authoritative "] {
            let mut other = running.clone();
            other.observation.coverage = coverage.into();
            assert_eq!(state_for(&other), "active", "{coverage:?}");
        }

        // And the two never tie: `working` outranks `active` when the card picks a primary row.
        assert!(state_priority("working") < state_priority("active"));
    }

    /// Every turn maps to exactly one word, and a persisted session with no worker is `stopped`
    /// no matter what turn it last recorded — the presence check runs before the turn is read,
    /// so a session that died mid-run cannot keep claiming to be running.
    #[test]
    fn each_turn_maps_to_one_state_and_stored_presence_wins_over_all_of_them() {
        let base = fixture_descriptor();
        let running = TurnState::Running {
            run_id: "run-a".into(),
            activity: "thinking".into(),
        };
        let cases = [
            (
                TurnState::AwaitingInteraction { run_id: None },
                "needs_input",
            ),
            (
                TurnState::Failed {
                    run_id: None,
                    category: "adapter".into(),
                },
                "failed",
            ),
            (running.clone(), "active"),
            (
                TurnState::Stopping {
                    run_id: "run-a".into(),
                },
                "stopping",
            ),
            (TurnState::Completed { run_id: None }, "done"),
            (TurnState::Interrupted { run_id: None }, "done"),
            (TurnState::Idle, "idle"),
            (
                TurnState::Unknown {
                    reason_code: "stale".into(),
                },
                "unknown",
            ),
            (TurnState::Unsupported, "unknown"),
        ];

        for (turn, expected) in cases {
            let mut live = base.clone();
            live.turn = turn.clone();
            assert_eq!(state_for(&live), expected, "{turn:?}");

            let mut stored = live;
            stored.presence = "stored".into();
            assert_eq!(state_for(&stored), "stopped", "{turn:?}");
        }
    }

    /// The three answers a session can get, and the precedence between them. A live descriptor
    /// speaks for its own session; a persisted record speaks only where none does; and a session
    /// neither owner knows about is `None`, which is how delivery keeps the labels captured at
    /// opt-in instead of inventing a claim.
    #[test]
    fn a_live_descriptor_outranks_a_stored_record_and_an_unknown_session_has_no_fact() {
        let mut descriptor = fixture_descriptor();
        descriptor.session_id = "session-live".into();
        descriptor.turn = TurnState::Idle;
        descriptor.adapter_family = "claude".into();
        descriptor.workspace_display = "ciao".into();
        descriptor.recent_prompt = Some("Fix the reconnect wedge".into());

        let stored = |session_id: &str, reason: Option<&str>| ManagedSessionSummary {
            session_id: session_id.to_owned(),
            presence: "stored".into(),
            stored_reason: reason.map(str::to_owned),
            workspace_label: "ciao".into(),
            process_generation: 1,
            updated_at: 100,
        };
        let mut live_record = stored("session-live", Some("worker_crash"));
        live_record.presence = "live".into();

        let overview = LiveActivityOverview::project(
            vec![descriptor],
            vec![
                // The same session persisted *and* live: the descriptor is the current truth.
                stored("session-live", Some("worker_crash")),
                stored("session-stopped", None),
                stored("session-crashed", Some("worker_crash")),
                // A live managed record is not a Live Activity claim; its descriptor is.
                live_record,
            ],
            &HashSet::new(),
        );

        let live = overview.fact("session-live").unwrap();
        assert_eq!(live.state, "idle");
        let labels = live.labels.clone().unwrap();
        assert_eq!(labels.agent, "claude");
        assert_eq!(labels.workspace, "ciao");
        assert_eq!(labels.prompt.as_deref(), Some("Fix the reconnect wedge"));

        // A persisted record carries a state and no labels — the row keeps its opt-in ones.
        assert_eq!(overview.fact("session-stopped").unwrap().state, "stopped");
        assert!(overview.fact("session-stopped").unwrap().labels.is_none());
        assert_eq!(overview.fact("session-crashed").unwrap().state, "failed");

        assert!(overview.fact("session-never-seen").is_none());
    }

    /// Spec 018 §7, amended 2026-08-19: a session the daemon watched end may say `stopped`.
    /// Removal used to erase the evidence — the row fell to `unknown` ("Watching") forever while
    /// the daemon had stood there and seen the process die. Absence without a verdict still
    /// proves nothing, and a verdict never masks a live claim: an informative descriptor wins
    /// outright, while one that only says `unknown` lends its fresher labels and defers the
    /// state to whichever owner actually knows.
    #[test]
    fn an_observed_end_beats_only_an_unknown_descriptor() {
        let descriptor = |session_id: &str, turn: TurnState| {
            let mut descriptor = fixture_descriptor();
            descriptor.session_id = session_id.into();
            descriptor.turn = turn;
            descriptor.workspace_display = "fresh-label".into();
            descriptor
        };
        let ended: HashSet<String> = [
            "session-swept".to_owned(),
            "session-downgraded".to_owned(),
            "session-revived".to_owned(),
            "session-crashed".to_owned(),
        ]
        .into();

        let overview = LiveActivityOverview::project(
            vec![
                // Downgraded after a vendor-announced end: still listed, turn unknown.
                descriptor(
                    "session-downgraded",
                    TurnState::Unknown {
                        reason_code: "session_ended".into(),
                    },
                ),
                // A live claim always wins over a verdict.
                descriptor(
                    "session-revived",
                    TurnState::Running {
                        run_id: "run-a".into(),
                        activity: "thinking".into(),
                    },
                ),
                descriptor(
                    "session-crashed",
                    TurnState::Unknown {
                        reason_code: "bridge_disconnected".into(),
                    },
                ),
            ],
            // The directory's word is more specific than a bare end verdict and outranks it.
            vec![ManagedSessionSummary {
                session_id: "session-crashed".into(),
                presence: "stored".into(),
                stored_reason: Some("worker_crash".into()),
                workspace_label: "ciao".into(),
                process_generation: 1,
                updated_at: 100,
            }],
            &ended,
        );

        // Watched die, no descriptor left: the verdict is the fact, labels stay the opt-in ones.
        let swept = overview.fact("session-swept").unwrap();
        assert_eq!(swept.state, "stopped");
        assert!(swept.labels.is_none());

        // Still listed but only `unknown`: the verdict keeps the state, the row keeps the
        // descriptor's fresher labels.
        let downgraded = overview.fact("session-downgraded").unwrap();
        assert_eq!(downgraded.state, "stopped");
        assert_eq!(downgraded.labels.as_ref().unwrap().workspace, "fresh-label");

        assert_eq!(overview.fact("session-revived").unwrap().state, "active");
        assert_eq!(overview.fact("session-crashed").unwrap().state, "failed");

        // No verdict and no owner: absence still proves nothing.
        assert!(overview.fact("session-never-seen").is_none());
    }

    /// Every label in the projection is text a person chose — a directory name, an adapter name a
    /// vendor picked, a prompt — so none of them may be trusted to be short, and an empty prompt
    /// is absence rather than an empty pair of quotation marks on a Lock Screen.
    #[test]
    fn projected_labels_are_cut_to_their_spec_018_bounds() {
        let mut descriptor = fixture_descriptor();
        descriptor.session_id = "session-1".into();
        descriptor.adapter_family = "a".repeat(4096);
        descriptor.workspace_display = "🧪".repeat(64);
        descriptor.recent_prompt = Some("🧪".repeat(64));

        let overview =
            LiveActivityOverview::project(vec![descriptor.clone()], Vec::new(), &HashSet::new());
        let labels = overview.fact("session-1").unwrap().labels.clone().unwrap();
        assert_eq!(labels.agent.len(), MAX_LIVE_ACTIVITY_ADAPTER_CHARACTERS);
        assert!(labels.workspace.len() <= MAX_LIVE_ACTIVITY_DISPLAY_BYTES);
        assert!(labels.workspace.ends_with('…'));
        let prompt = labels.prompt.unwrap();
        assert!(prompt.len() <= MAX_LIVE_ACTIVITY_DISPLAY_BYTES);
        assert!(prompt.ends_with('…'));

        // A value that fits is left exactly alone.
        assert_eq!(
            bounded_utf8("ciao", MAX_LIVE_ACTIVITY_DISPLAY_BYTES),
            "ciao"
        );

        for absent in [None, Some(String::new())] {
            let mut empty = descriptor.clone();
            empty.recent_prompt = absent;
            let overview = LiveActivityOverview::project(vec![empty], Vec::new(), &HashSet::new());
            assert!(
                overview
                    .fact("session-1")
                    .unwrap()
                    .labels
                    .as_ref()
                    .unwrap()
                    .prompt
                    .is_none()
            );
        }
    }

    /// The canonical Spec 005 descriptor, which is also the one the phone's own tests read.
    fn fixture_descriptor() -> AgentSessionDescriptor {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase4/agent-session-v1.json"
        );
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        serde_json::from_value(fixture["list"]["sessions"][0].clone()).unwrap()
    }
}
