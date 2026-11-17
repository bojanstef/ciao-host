//! Session-scoped observations. The parent's own turn stays intact while descendants work.
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent_adapter::validate_frame_header;
use crate::agent_protocol::{AgentProtocolError, TurnState, valid_opaque_id};

pub(crate) const MAX_CHILDREN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChildState {
    #[serde(skip)]
    Unobserved,
    Started,
    Observed,
    BackgroundSnapshot,
    Progress,
    Waiting,
    Finished,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChildReport {
    pub(crate) ids: Vec<String>,
    pub(crate) state: ChildState,
    /// Capture before a transient hook's asynchronous process/version checks.
    pub(crate) observed_us: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) overflow: bool,
}

impl ChildReport {
    pub(crate) fn validate(&self) -> Result<(), AgentProtocolError> {
        if self.observed_us == 0
            || self.ids.len() > MAX_CHILDREN
            || (self.state != ChildState::BackgroundSnapshot
                && (self.ids.len() != 1 || self.overflow))
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        for id in &self.ids {
            valid_opaque_id(id)?;
        }
        Ok(())
    }

    pub(crate) fn one(id: String, state: ChildState, observed_us: u64) -> Self {
        Self {
            ids: vec![id],
            state,
            observed_us,
            overflow: false,
        }
    }
}

pub(crate) fn observation_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

pub(crate) fn decode(value: Value, version: u8) -> Result<ChildReport, AgentProtocolError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Frame {
        v: u8,
        #[serde(rename = "type")]
        kind: String,
        report: ChildReport,
    }
    let f: Frame = serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)?;
    validate_frame_header(f.v, version, &f.kind, "child_activity")?;
    f.report.validate()?;
    Ok(f.report)
}

#[derive(Debug)]
struct Record {
    state: ChildState,
    stamp: u64,
    // Expiry uses the host's own clock. The producer stamp only orders deliveries.
    received: u64,
    stale: bool,
    background: bool,
}

#[derive(Debug, Default)]
pub(crate) struct ChildActivity {
    records: BTreeMap<String, Record>,
    forgotten_through: u64,
    last_background_snapshot: u64,
    background_incomplete: bool,
    incomplete: bool,
}

impl ChildActivity {
    pub(crate) fn contains(&self, id: &str) -> bool {
        self.records.contains_key(id)
    }

    /// A superseded background inventory must not deliver its accompanying parent stop either.
    pub(crate) fn apply(&mut self, report: ChildReport, now: u64) -> bool {
        let snapshot = report.state == ChildState::BackgroundSnapshot;
        if snapshot {
            if report.observed_us <= self.last_background_snapshot {
                return false;
            }
            self.last_background_snapshot = report.observed_us;
            self.background_incomplete = report.overflow;
        }
        if snapshot && !report.overflow {
            for (id, child) in &mut self.records {
                if child.background && child.stamp <= report.observed_us && !report.ids.contains(id)
                {
                    child.state = ChildState::Finished;
                    child.stamp = report.observed_us;
                    child.stale = false;
                }
            }
        }
        for id in report.ids {
            if let Some(old) = self.records.get(&id) {
                if report.state == ChildState::Unobserved
                    || report.observed_us < old.stamp
                    || (report.observed_us == old.stamp && old.state == ChildState::Finished)
                    || (old.state == ChildState::Finished
                        && matches!(report.state, ChildState::Observed | ChildState::Progress))
                {
                    continue;
                }
            } else {
                if report.observed_us <= self.forgotten_through {
                    // This ID may have had a newer finish evicted. A positive report here
                    // proves neither a live child nor a settled family.
                    self.incomplete |= report.state != ChildState::Finished;
                    continue;
                }
                if self.records.len() == MAX_CHILDREN {
                    let oldest = self
                        .records
                        .iter()
                        .filter(|(_, r)| r.state == ChildState::Finished)
                        .min_by_key(|(_, r)| r.stamp)
                        .map(|(id, r)| (id.clone(), r.stamp));
                    let Some((key, stamp)) = oldest else {
                        self.incomplete |= report.state != ChildState::Finished;
                        continue;
                    };
                    self.records.remove(&key);
                    self.forgotten_through = self.forgotten_through.max(stamp);
                }
            }
            // A parent snapshot proves this child is live but cannot clear its permission wait.
            let background = snapshot
                || (report.state != ChildState::Started
                    && self.records.get(&id).is_some_and(|r| r.background));
            let state = if matches!(
                report.state,
                ChildState::Observed | ChildState::BackgroundSnapshot
            ) && self
                .records
                .get(&id)
                .is_some_and(|r| r.state == ChildState::Waiting)
            {
                ChildState::Waiting
            } else {
                report.state
            };
            self.records.insert(
                id,
                Record {
                    state,
                    stamp: report.observed_us,
                    received: now,
                    stale: false,
                    background,
                },
            );
        }
        true
    }

    pub(crate) fn expire(&mut self, now: u64, limit: u64) {
        for r in self.records.values_mut() {
            if r.state != ChildState::Finished && now.saturating_sub(r.received) >= limit {
                r.stale = true;
            }
        }
    }

    pub(crate) fn turn(&self, parent: &TurnState) -> TurnState {
        use TurnState::*;
        if self.records.is_empty() && !self.incomplete && !self.background_incomplete {
            return parent.clone();
        }
        if matches!(parent, AwaitingInteraction { .. } | Failed { .. }) {
            return parent.clone();
        }
        let run = parent.run_id().cloned();
        let mut active = None;
        let mut uncertain = self.incomplete || self.background_incomplete;
        for (id, r) in &self.records {
            if r.state == ChildState::Finished {
                continue;
            }
            if r.stale || r.state == ChildState::Unobserved {
                uncertain = true;
                continue;
            }
            if r.state == ChildState::Waiting {
                return AwaitingInteraction { run_id: run };
            }
            active.get_or_insert(id);
        }
        if matches!(parent, Running { .. } | Stopping { .. }) {
            return parent.clone();
        }
        if let Some(id) = active {
            return Running {
                run_id: run.unwrap_or_else(|| id.clone()),
                activity: "subagents".into(),
            };
        }
        if uncertain {
            return Unknown {
                reason_code: "subagent_state_unknown".into(),
            };
        }
        parent.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ChildState::*;

    fn done() -> TurnState {
        TurnState::Completed {
            run_id: Some("parent".into()),
        }
    }
    fn snapshot(ids: &[&str], stamp: u64) -> ChildReport {
        ChildReport {
            ids: ids.iter().map(|id| id.to_string()).collect(),
            state: BackgroundSnapshot,
            observed_us: stamp,
            overflow: false,
        }
    }

    #[test]
    fn stale_children_and_delayed_hooks_cannot_invent_completion_or_resurrect_a_finished_child() {
        let mut children = ChildActivity::default();
        let event = |s, t| ChildReport::one("agent".into(), s, t);
        children.apply(event(Started, 1), 400);
        children.expire(415, 15);
        assert!(matches!(children.turn(&done()), TurnState::Unknown { .. }));
        children.apply(event(Finished, 4), 418);
        for _ in 0..2 {
            children.apply(event(Started, 3), 420);
            assert_eq!(children.turn(&done()), done());
        }
        children.apply(event(Started, 5), 420);
        assert!(matches!(children.turn(&done()), TurnState::Running { .. }));
    }

    #[test]
    fn a_background_snapshot_reconciles_only_its_members_and_preserves_newer_evidence() {
        let mut c = ChildActivity::default();
        c.apply(ChildReport::one("foreground".into(), Started, 1), 1);
        c.apply(snapshot(&["background"], 2), 2);
        c.apply(ChildReport::one("background".into(), Waiting, 5), 5);
        c.apply(snapshot(&[], 4), 6);
        c.apply(snapshot(&["background"], 6), 7);
        assert!(matches!(
            c.turn(&done()),
            TurnState::AwaitingInteraction { .. }
        ));
        c.apply(snapshot(&[], 8), 8);
        assert!(matches!(c.turn(&done()), TurnState::Running { .. }));
        c.apply(ChildReport::one("foreground".into(), Finished, 9), 9);
        assert_eq!(c.turn(&done()), done());
        c.apply(snapshot(&["unseen"], 7), 10);
        assert_eq!(c.turn(&done()), done());
        c.apply(snapshot(&["background"], 10), 10);
        assert!(matches!(c.turn(&done()), TurnState::Running { .. }));
    }

    #[test]
    fn a_later_complete_inventory_can_restore_certainty_about_background_work() {
        let mut c = ChildActivity::default();
        c.apply(
            ChildReport {
                overflow: true,
                ..snapshot(&[], 3)
            },
            3,
        );
        assert!(matches!(c.turn(&done()), TurnState::Unknown { .. }));
        c.apply(snapshot(&[], 4), 4);
        assert_eq!(c.turn(&done()), done());
    }

    #[test]
    fn exhausting_the_bound_with_live_children_withdraws_certainty() {
        let mut c = ChildActivity::default();
        for i in 0..=MAX_CHILDREN {
            c.apply(ChildReport::one(i.to_string(), Started, i as u64 + 1), 1);
        }
        for i in 0..MAX_CHILDREN {
            c.apply(
                ChildReport::one(i.to_string(), Finished, (i + MAX_CHILDREN) as u64 + 1),
                2,
            );
        }
        assert_eq!(c.records.len(), MAX_CHILDREN);
        assert!(matches!(c.turn(&done()), TurnState::Unknown { .. }));
    }
}
