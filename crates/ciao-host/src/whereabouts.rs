//! Where the person typing to an attached agent is, so the agent hears when that changes
//! (Spec 025).
//!
//! The question is "can the person see this machine's screen right now", asked at the one moment
//! it has an answer: a person just submitted a prompt. Two observations answer it, and only
//! positive evidence moves the answer:
//!
//! - this Mac's own keyboard or mouse was touched within [`AT_HOST_WINDOW`] — pressing Enter here
//!   does exactly that — so the person is at it;
//! - otherwise a paired device typed into one of this host's terminals within [`DEVICE_WINDOW`],
//!   so the person is away, on Ciao.
//!
//! Neither (a prompt queued earlier, SSH from somewhere else) leaves the session's answer where it
//! was. A host whose local input this daemon cannot observe — every Linux host today — is always
//! remote: whichever way the person reached it, its screen is not in front of them.
//!
//! The agent hears a note only when its answer changes, and once more after anything that may have
//! dropped or outdated the last one (compaction, resume, clear). A conversation that never left
//! the Mac never hears anything: at the Mac is what every agent assumes already.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

/// Hook delivery reaches the daemon within about a second of Enter; the rest is margin for a busy
/// host. Kept short on purpose: misreading "away" as "at the Mac" is the costly direction, since
/// the agent may then rely on a screen nobody is looking at.
pub(crate) const AT_HOST_WINDOW: Duration = Duration::from_secs(3);
/// The device's last keystroke is the Enter that submitted the prompt, so this only has to cover
/// the PTY → multiplexer → agent → hook path, with room for a loaded host.
pub(crate) const DEVICE_WINDOW: Duration = Duration::from_secs(10);
/// A slice of the hook's own delivery budget (`HOOK_DELIVERY_TIMEOUT`), which the probe runs
/// inside. A probe that loses this race reads as "no evidence", never as either answer.
#[cfg(all(target_os = "macos", not(test)))]
const HOST_INPUT_PROBE_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Location {
    /// This Mac's own input moved moments before the prompt arrived.
    AtHost,
    /// A paired device typed the prompt while this Mac's input sat idle.
    Away,
    /// A host with no local input this daemon can observe; every prompt to it is remote.
    Remote,
}

impl Location {
    pub(crate) fn token(self) -> &'static str {
        match self {
            Self::AtHost => "at_host",
            Self::Away => "away",
            Self::Remote => "remote",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostInput {
    /// This platform offers no local input signal at all.
    #[cfg_attr(
        all(target_os = "macos", not(test)),
        allow(
            dead_code,
            reason = "only a host without a local input probe constructs it"
        )
    )]
    Unobservable,
    /// The probe failed or ran out of time. Says nothing either way.
    #[cfg_attr(
        all(not(target_os = "macos"), not(test)),
        allow(
            dead_code,
            reason = "only a host with a local input probe constructs it"
        )
    )]
    Unreadable,
    #[cfg_attr(
        all(not(target_os = "macos"), not(test)),
        allow(
            dead_code,
            reason = "only a host with a local input probe constructs it"
        )
    )]
    IdleFor(Duration),
}

impl HostInput {
    pub(crate) fn token(self) -> &'static str {
        match self {
            Self::Unobservable => "unobservable",
            Self::Unreadable => "unreadable",
            Self::IdleFor(_) => "idle",
        }
    }

    pub(crate) fn idle_ms(self) -> Option<u128> {
        match self {
            Self::IdleFor(idle) => Some(idle.as_millis()),
            Self::Unobservable | Self::Unreadable => None,
        }
    }
}

/// What the daemon saw when one prompt arrived. Kept whole so the decision can be logged together
/// with the inputs it turned on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Evidence {
    pub(crate) host: HostInput,
    pub(crate) device_idle: Option<Duration>,
}

impl Evidence {
    pub(crate) fn location(self) -> Option<Location> {
        locate(self.host, self.device_idle)
    }
}

/// The location one prompt's evidence supports, or `None` when it supports nothing.
pub(crate) fn locate(host: HostInput, device_idle: Option<Duration>) -> Option<Location> {
    match host {
        HostInput::Unobservable => Some(Location::Remote),
        HostInput::IdleFor(idle) if idle < AT_HOST_WINDOW => Some(Location::AtHost),
        HostInput::IdleFor(_) | HostInput::Unreadable => device_idle
            .is_some_and(|idle| idle < DEVICE_WINDOW)
            .then_some(Location::Away),
    }
}

/// What one conversation's agent was last told. Owned by the session it describes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Announced {
    last: Option<Location>,
    /// Whether this conversation was ever told the person is away. After a reset that is what
    /// makes "at the Mac" worth saying: a compaction summary or a resumed history can still claim
    /// otherwise.
    ever_away: bool,
}

impl Announced {
    /// The location to tell the agent with this prompt, when it differs from what it last heard.
    pub(crate) fn on_prompt(&mut self, location: Location) -> Option<Location> {
        if self.last == Some(location) {
            return None;
        }
        let assumed = self.last.is_none() && location == Location::AtHost && !self.ever_away;
        self.last = Some(location);
        self.ever_away |= location != Location::AtHost;
        (!assumed).then_some(location)
    }

    /// The agent's context was rebuilt — compacted, resumed, cleared — so whatever it was told may
    /// be gone. The next prompt says where the person is again.
    pub(crate) fn reset(&mut self) {
        self.last = None;
    }
}

/// The daemon's evidence about where its person is: one per daemon, cheap to clone.
#[derive(Debug, Clone, Default)]
pub(crate) struct Whereabouts {
    device_input: Arc<Mutex<Option<Instant>>>,
    #[cfg(test)]
    host_input: Arc<Mutex<Option<HostInput>>>,
}

impl Whereabouts {
    /// A paired device just wrote to one of this host's terminals.
    pub(crate) fn note_device_input(&self) {
        *self.device_input.lock() = Some(Instant::now());
    }

    pub(crate) async fn observe(&self) -> Evidence {
        let device_idle = self.device_input.lock().map(|at| at.elapsed());
        Evidence {
            host: self.host_input().await,
            device_idle,
        }
    }

    #[cfg(not(test))]
    async fn host_input(&self) -> HostInput {
        host_input().await
    }

    /// Tests never read the real keyboard: whoever runs them is at it.
    #[cfg(test)]
    async fn host_input(&self) -> HostInput {
        self.host_input.lock().unwrap_or(HostInput::Unreadable)
    }

    #[cfg(test)]
    pub(crate) fn set_host_input(&self, input: HostInput) {
        *self.host_input.lock() = Some(input);
    }

    #[cfg(test)]
    pub(crate) fn note_device_input_at(&self, at: Instant) {
        *self.device_input.lock() = Some(at);
    }
}

/// `ioreg` rather than `CGEventSourceSecondsSinceLastEventType`: the same IOHIDSystem counter,
/// without lifting the crate's `unsafe_code = "forbid"` for one FFI call. Measured under 10 ms.
#[cfg(all(target_os = "macos", not(test)))]
async fn host_input() -> HostInput {
    let probe = crate::workspace::run_bounded(
        std::path::Path::new("/usr/sbin/ioreg"),
        &["-r", "-c", "IOHIDSystem", "-d", "1", "-k", "HIDIdleTime"],
    );
    match tokio::time::timeout(HOST_INPUT_PROBE_TIMEOUT, probe).await {
        Ok(Ok(output)) if output.status_success && !output.stdout_truncated => {
            parse_hid_idle(&output.stdout).map_or(HostInput::Unreadable, HostInput::IdleFor)
        }
        _ => HostInput::Unreadable,
    }
}

#[cfg(all(not(target_os = "macos"), not(test)))]
async fn host_input() -> HostInput {
    HostInput::Unobservable
}

/// `"HIDIdleTime" = <nanoseconds>` out of `ioreg`'s tree, whatever its indentation.
#[cfg(any(target_os = "macos", test))]
fn parse_hid_idle(stdout: &[u8]) -> Option<Duration> {
    String::from_utf8_lossy(stdout)
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            key.trim_end()
                .ends_with("\"HIDIdleTime\"")
                .then(|| value.trim().parse::<u64>().ok())
                .flatten()
        })
        .map(Duration::from_nanos)
}

const AWAY_NOTE: &str = "\
Where the user is: away from this Mac, typing from the Ciao app on their phone. They can't see \
or click anything on this Mac's screen. This limits only the user, not you: keep using the \
simulator, browsers, GUI apps and anything else as you normally would.
- When a step needs the user to see or click something on the Mac (a browser login, a permission \
or Keychain dialog), it won't reach them. Prefer a flow they can finish from their phone: give the \
URL and code as text (for `gh auth login`: the github.com/login/device link and the code).
- If no such flow exists, tell them what is waiting on the Mac and why, then carry on with \
anything that doesn't depend on it.
- Write localhost URLs and absolute file paths in full. In Ciao, the user long-presses them to \
open the page or preview the file. To show them something on screen, save a screenshot and give \
its absolute path.
This replaces any earlier note about where the user is. Start your reply with one short line \
confirming it, e.g. \"(Noted: you're away from the Mac.)\"";

const AT_HOST_NOTE: &str = "\
Where the user is: at this Mac. They can see and click things on its screen again. This replaces \
any earlier note about where the user is. Start your reply with one short line confirming it, \
e.g. \"(Noted: you're back at the Mac.)\"";

/// The text the agent reads. Owned here, once, for every vendor that can carry it.
pub(crate) fn note(location: Location) -> String {
    match location {
        Location::Away => AWAY_NOTE.into(),
        Location::AtHost => AT_HOST_NOTE.into(),
        Location::Remote => {
            remote_note(&crate::host_info::display_name().unwrap_or_else(|| "this machine".into()))
        }
    }
}

fn remote_note(host: &str) -> String {
    format!(
        "\
Where the user is: this is a remote machine ({host}). The user reaches it from the Ciao app on \
their phone or over SSH, so they can't see or click anything that opens on its screen. This \
limits only the user, not you.
- For logins, use a flow the user can finish on their own device: give the URL and code as text.
- Write localhost URLs and absolute file paths in full. In Ciao, the user long-presses them to \
open the page or preview the file. To show them something visual, save a screenshot and give its \
absolute path.
This replaces any earlier note about where the user is. Start your reply with one short line \
confirming it, e.g. \"(Noted: remote session on {host}.)\""
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const LONG_AGO: Duration = Duration::from_secs(600);

    #[test]
    fn local_input_wins_and_device_input_is_the_only_evidence_of_away() {
        let just_now = Some(Duration::from_millis(400));
        // Enter pressed on this Mac: at it, whatever a device did at the same moment.
        assert_eq!(
            locate(HostInput::IdleFor(Duration::from_millis(200)), just_now),
            Some(Location::AtHost)
        );
        // Idle Mac, device typed: away.
        assert_eq!(
            locate(HostInput::IdleFor(LONG_AGO), just_now),
            Some(Location::Away)
        );
        // Idle Mac, no device either — a queued prompt, SSH, automation: no evidence.
        assert_eq!(locate(HostInput::IdleFor(LONG_AGO), None), None);
        assert_eq!(locate(HostInput::IdleFor(LONG_AGO), Some(LONG_AGO)), None);
        // A failed probe is not "at the Mac"; the device can still prove away.
        assert_eq!(
            locate(HostInput::Unreadable, just_now),
            Some(Location::Away)
        );
        assert_eq!(locate(HostInput::Unreadable, None), None);
        // No local input to observe at all: always remote.
        assert_eq!(
            locate(HostInput::Unobservable, None),
            Some(Location::Remote)
        );
        assert_eq!(
            locate(HostInput::Unobservable, just_now),
            Some(Location::Remote)
        );
    }

    #[test]
    fn windows_are_exclusive_at_their_edge() {
        assert_eq!(
            locate(HostInput::IdleFor(AT_HOST_WINDOW), None),
            None,
            "exactly the window is already idle"
        );
        assert_eq!(
            locate(HostInput::IdleFor(LONG_AGO), Some(DEVICE_WINDOW)),
            None
        );
    }

    #[test]
    fn a_conversation_hears_each_change_once_in_either_direction() {
        let mut announced = Announced::default();
        // Started at the Mac: the default, so nothing is said.
        assert_eq!(announced.on_prompt(Location::AtHost), None);
        assert_eq!(announced.on_prompt(Location::AtHost), None);
        assert_eq!(announced.on_prompt(Location::Away), Some(Location::Away));
        assert_eq!(announced.on_prompt(Location::Away), None);
        assert_eq!(
            announced.on_prompt(Location::AtHost),
            Some(Location::AtHost)
        );
        assert_eq!(announced.on_prompt(Location::Away), Some(Location::Away));
    }

    #[test]
    fn a_conversation_started_away_hears_it_on_its_first_prompt() {
        let mut announced = Announced::default();
        assert_eq!(announced.on_prompt(Location::Away), Some(Location::Away));
        let mut remote = Announced::default();
        assert_eq!(remote.on_prompt(Location::Remote), Some(Location::Remote));
        assert_eq!(remote.on_prompt(Location::Remote), None);
    }

    #[test]
    fn a_reset_repeats_the_answer_unless_the_conversation_never_left_the_mac() {
        let mut stayed = Announced::default();
        assert_eq!(stayed.on_prompt(Location::AtHost), None);
        stayed.reset();
        assert_eq!(stayed.on_prompt(Location::AtHost), None);

        let mut travelled = Announced::default();
        assert_eq!(travelled.on_prompt(Location::Away), Some(Location::Away));
        assert_eq!(
            travelled.on_prompt(Location::AtHost),
            Some(Location::AtHost)
        );
        travelled.reset();
        // The summary may still say "away"; at the Mac is worth saying now.
        assert_eq!(
            travelled.on_prompt(Location::AtHost),
            Some(Location::AtHost)
        );

        let mut still_away = Announced::default();
        assert_eq!(still_away.on_prompt(Location::Away), Some(Location::Away));
        still_away.reset();
        assert_eq!(still_away.on_prompt(Location::Away), Some(Location::Away));
    }

    #[tokio::test]
    async fn whereabouts_read_device_recency_against_the_host_probe() {
        let whereabouts = Whereabouts::default();
        whereabouts.set_host_input(HostInput::IdleFor(LONG_AGO));
        assert_eq!(
            whereabouts.observe().await.location(),
            None,
            "no device input yet"
        );
        whereabouts.note_device_input();
        assert_eq!(whereabouts.observe().await.location(), Some(Location::Away));
        if let Some(stale) = Instant::now().checked_sub(LONG_AGO) {
            whereabouts.note_device_input_at(stale);
            assert_eq!(whereabouts.observe().await.location(), None);
        }
        whereabouts.set_host_input(HostInput::IdleFor(Duration::ZERO));
        assert_eq!(
            whereabouts.observe().await.location(),
            Some(Location::AtHost)
        );
    }

    #[test]
    fn hid_idle_parses_from_the_ioreg_tree() {
        let stdout = b"+-o IOHIDSystem  <class IOHIDSystem, id 0x100000a1b>\n    {\n      \"HIDIdleTime\" = 40916733958\n    }\n";
        assert_eq!(
            parse_hid_idle(stdout),
            Some(Duration::from_nanos(40_916_733_958))
        );
        let nested = b"    | |     \"HIDIdleTime\" = 125\n";
        assert_eq!(parse_hid_idle(nested), Some(Duration::from_nanos(125)));
        assert_eq!(parse_hid_idle(b"\"HIDIdleTimeX\" = 5\n"), None);
        assert_eq!(parse_hid_idle(b"\"HIDIdleTime\" = soon\n"), None);
        assert_eq!(parse_hid_idle(b""), None);
    }

    #[test]
    fn every_note_replaces_the_last_and_asks_for_a_confirmation() {
        for location in [Location::AtHost, Location::Away, Location::Remote] {
            let text = note(location);
            assert!(text.starts_with("Where the user is: "), "{location:?}");
            assert!(
                text.contains("replaces any earlier note about where the user is"),
                "{location:?}"
            );
            assert!(text.contains("(Noted: "), "{location:?}");
        }
        assert!(remote_note("fixture-host").contains("(Noted: remote session on fixture-host.)"));
    }
}
