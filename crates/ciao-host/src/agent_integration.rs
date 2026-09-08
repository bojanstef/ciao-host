//! Explicit CLI dispatch for installed agent integrations.
//!
//! Installation remains vendor-specific and merge-safe. One provider token may orchestrate
//! multiple Ciao-owned surfaces for that provider, but each installer keeps its own ownership
//! boundary and never turns into an implicit universal integration.

use anyhow::{Result, anyhow};
use clap::ValueEnum;

use crate::{
    claude_adapter::PINNED_CLAUDE_VERSION,
    claude_integration::{
        claude_integration_status, install_claude_plugin, uninstall_claude_plugin,
    },
    claude_managed_integration::{
        install_managed_claude, managed_claude_status, uninstall_managed_claude,
    },
    codex_adapter::PINNED_CODEX_VERSION,
    codex_integration::{
        CodexIntegrationStatus, codex_integration_status, install_codex_hooks,
        require_pinned_codex_version, uninstall_codex_hooks,
    },
    pi_integration::{install_pi_extension, pi_integration_status, uninstall_pi_extension},
    storage::CiaoPaths,
};

fn install_claude_components(
    install_attached: impl FnOnce() -> Result<()>,
    install_managed: impl FnOnce() -> Result<()>,
) -> Result<String> {
    // Try both independent surfaces. In particular, an auto-updated user Claude is outside the
    // attached pin on most machines, while the SDK pair is still installable; that must not
    // leave yesterday's worker in place. And because the managed runtime is what the Agents tab
    // runs on, hooks-only trouble is a skip note on a successful install, not a failure: exiting
    // nonzero here taught people the whole thing was broken while the headline feature worked.
    let managed = install_managed();
    let attached = install_attached();
    match (attached, managed) {
        (Ok(()), Ok(())) => Ok("✓ Claude is set up. The Agents tab can start sessions on this host, and sessions you start in your own terminal appear in the app too.".into()),
        (Err(reason), Ok(())) => Ok(format!(
            "✓ Managed Claude runtime installed — the Agents tab can start sessions on this host.\n○ Read-only hooks skipped: {reason:#}.\n  Sessions you start in your own terminal won't appear in the app; everything the Agents tab starts will."
        )),
        (Ok(()), Err(error)) => {
            Err(error
                .context("Claude's read-only hooks are installed, but the managed runtime is not"))
        }
        (Err(attached), Err(managed)) => Err(anyhow!(
            "neither Claude component could be installed; read-only hooks: {attached:#}; managed runtime: {managed:#}"
        )),
    }
}

fn uninstall_claude_components(
    uninstall_attached: impl FnOnce() -> Result<bool>,
    uninstall_managed: impl FnOnce() -> Result<bool>,
) -> Result<bool> {
    let managed = uninstall_managed();
    let attached = uninstall_attached();
    match (attached, managed) {
        (Ok(attached), Ok(managed)) => Ok(attached || managed),
        (Err(error), Ok(managed_removed)) => Err(error.context(if managed_removed {
            "the managed runtime was removed, but the read-only hooks were not"
        } else {
            "the managed runtime was not installed, and the read-only hooks could not be removed"
        })),
        (Ok(attached_removed), Err(error)) => Err(error.context(if attached_removed {
            "the read-only hooks were removed, but the managed runtime was not"
        } else {
            "the read-only hooks were not installed, and the managed runtime could not be removed"
        })),
        (Err(attached), Err(managed)) => Err(anyhow!(
            "neither Claude component could be removed; read-only hooks: {attached:#}; managed runtime: {managed:#}"
        )),
    }
}

/// Separated from the install arm only so a test can hold the wording: the defect this replaces
/// was entirely in the wording, and it is not reachable from a unit test through the arm itself
/// (that path shells out to `codex --version`).
fn codex_pin_miss_note(reason: &anyhow::Error) -> String {
    format!(
        "○ Codex read-only hooks skipped: {reason:#}.\n  Your own Codex sessions won't appear in the app until Ciao on this host supports that version. Nothing else about Ciao is affected."
    )
}

fn format_claude_status(attached: &str, managed: &str) -> String {
    format!(
        "Ciao Claude integrations:\n  Attached hooks (read-only, Claude Code {PINNED_CLAUDE_VERSION}+): {attached}\n  Managed runtime (headless, no terminal window): {managed}"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum AgentIntegration {
    Pi,
    /// Both Ciao-owned Claude surfaces: attached read-only hooks and the managed runtime.
    Claude,
    // Preserve the old managed-only operation for deployed scripts, but do not list it as a
    // second integration. New instructions and UI always name `claude`.
    #[value(hide = true)]
    ClaudeManaged,
    /// Read-only attached Codex sessions (Spec 012). Merges into the user's own
    /// `~/.codex/hooks.json` alongside herdr's entry rather than owning a directory.
    Codex,
}

impl AgentIntegration {
    /// The token a person types for this integration — `ciao agent install <this>` — so setup's
    /// picker and error lines speak the same vocabulary as the CLI surface.
    pub(crate) fn cli_name(self) -> &'static str {
        match self {
            Self::Pi => "pi",
            Self::Claude => "claude",
            Self::ClaudeManaged => "claude-managed",
            Self::Codex => "codex",
        }
    }

    pub(crate) async fn install(self, paths: &CiaoPaths) -> Result<String> {
        match self {
            Self::Pi => {
                install_pi_extension(paths)?;
                Ok("Ciao's Pi Agent Session extension is installed. Start Pi normally, or use /reload in an existing Pi TUI.".into())
            }
            Self::Claude => install_claude_components(
                || install_claude_plugin(paths).map(|_| ()),
                || install_managed_claude(paths),
            ),
            Self::ClaudeManaged => {
                install_managed_claude(paths)?;
                Ok("Ciao's managed Claude runtime is installed. The `claude-managed` spelling is retained for compatibility; use `ciao agent install claude` for normal setup.".into())
            }
            // A pin miss is a skip, not a failure. Codex auto-updates the way Claude does, so
            // before this the common case for a Codex-using friend was a red `✗ not installed`
            // line during setup for something that was working fine yesterday and will work
            // again on the next host release.
            //
            // Asking before installing, rather than parsing the error afterwards, is what makes
            // this a skip for exactly one cause: every other install failure still returns Err
            // and still prints as one. That was the "typed pin-miss error" this needed — no new
            // error type, just the question asked in the right order.
            //
            // Attached hooks are Codex's only surface, so unlike Claude's skip note there is no
            // working remainder to point at. It says so instead of implying one.
            Self::Codex => {
                if let Err(reason) = require_pinned_codex_version(paths).await {
                    return Ok(codex_pin_miss_note(&reason));
                }
                // Codex refuses to run a hook it has not been told to trust, so an install that
                // stopped here would report a live tail that does not exist. The status read
                // afterwards is what turns that into a sentence the person can act on.
                Ok(match install_codex_hooks(paths).await? {
                    CodexIntegrationStatus::AwaitingTrust => {
                        "Ciao's read-only Codex hooks are installed, but Codex has not been told to trust them yet, so nothing is being observed. Start `codex` once and approve the new hooks when it asks."
                            .into()
                    }
                    _ => "Ciao's read-only Codex Agent Session hooks are installed. Start Codex normally; your own hooks were left untouched."
                        .to_owned(),
                })
            }
        }
    }

    pub(crate) async fn uninstall(self, paths: &CiaoPaths) -> Result<String> {
        match self {
            Self::Pi if uninstall_pi_extension(paths)? => Ok(
                "Ciao's Pi Agent Session extension was removed. Existing Pi sessions and other extensions were preserved."
                    .into(),
            ),
            Self::Pi => Ok("Ciao's Pi Agent Session extension is not installed.".into()),
            Self::Claude => {
                let removed = uninstall_claude_components(
                    || uninstall_claude_plugin(paths),
                    || uninstall_managed_claude(paths),
                )?;
                if removed {
                    Ok("Ciao's Claude integrations were removed. Your Claude installation, configuration, sessions, and other skills/plugins were preserved.".into())
                } else {
                    Ok("Ciao's Claude integrations are not installed.".into())
                }
            }
            Self::ClaudeManaged if uninstall_managed_claude(paths)? => Ok(
                "Ciao's managed Claude runtime was removed. Your own Claude installation, configuration, and sessions were preserved."
                    .into(),
            ),
            Self::ClaudeManaged => Ok("Ciao's managed Claude runtime is not installed.".into()),
            Self::Codex if uninstall_codex_hooks(paths)? => Ok(
                "Ciao's Codex Agent Session hooks were removed. Every other hook in that file, and its ordering, were preserved."
                    .into(),
            ),
            Self::Codex => Ok("Ciao's Codex Agent Session hooks are not installed.".into()),
        }
    }

    pub(crate) async fn status(self, paths: &CiaoPaths) -> Result<String> {
        let mut message = match self {
            Self::Pi => format!(
                "Ciao Pi Agent Session extension: {}",
                pi_integration_status(paths)?.label()
            ),
            Self::Claude => format_claude_status(
                claude_integration_status(paths)?.label(),
                &managed_claude_status(paths),
            ),
            Self::ClaudeManaged => format!(
                "Ciao managed Claude runtime (headless, no terminal window): {}",
                managed_claude_status(paths)
            ),
            Self::Codex => format!(
                "Ciao Codex Agent Session hooks (read-only, Codex {PINNED_CODEX_VERSION}): {}",
                codex_integration_status(paths).await?.label()
            ),
        };
        // Spec 017 §4.5: the tally of what this vendor sent that the build did not recognize.
        // Absence of the ledger is absence of drift, never an error.
        if let Some(ledger) =
            crate::drift::load(&paths.run_dir.join(crate::drift::LEDGER_FILE_NAME))
        {
            for vendor in self.drift_vendors() {
                let distinct = ledger.distinct_for(vendor);
                if distinct > 0 {
                    message.push_str(&format!(
                        "\n  {vendor} sent {distinct} kinds of input this build does not recognize. Run `ciao drift` for the list."
                    ));
                }
            }
        }
        Ok(message)
    }

    /// The drift-ledger vendor tokens this integration answers for. `claude` covers both the
    /// attached hooks and the transcript reads; the managed worker tallies under its own name.
    fn drift_vendors(self) -> &'static [&'static str] {
        match self {
            Self::Pi => &["pi"],
            Self::Claude => &["claude", "claude-managed"],
            Self::ClaudeManaged => &["claude-managed"],
            Self::Codex => &["codex"],
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use anyhow::anyhow;

    use super::*;

    #[test]
    fn provider_tokens_are_explicit_and_stable() {
        assert_eq!(
            AgentIntegration::from_str("pi", false),
            Ok(AgentIntegration::Pi)
        );
        assert_eq!(
            AgentIntegration::from_str("claude", false),
            Ok(AgentIntegration::Claude)
        );
        assert_eq!(
            AgentIntegration::from_str("claude-managed", false),
            Ok(AgentIntegration::ClaudeManaged),
            "the former managed-only command remains compatible"
        );
        let visible: Vec<_> = AgentIntegration::value_variants()
            .iter()
            .copied()
            .filter(|integration| {
                !integration
                    .to_possible_value()
                    .expect("every integration has a value")
                    .is_hide_set()
            })
            .collect();
        assert_eq!(
            visible,
            [
                AgentIntegration::Pi,
                AgentIntegration::Claude,
                AgentIntegration::Codex
            ],
            "help and completions expose one Claude integration"
        );
        assert_eq!(
            AgentIntegration::from_str("codex", false),
            Ok(AgentIntegration::Codex)
        );
    }

    #[test]
    fn one_claude_install_orchestrates_both_internal_components_in_order() {
        let calls = RefCell::new(Vec::new());
        install_claude_components(
            || {
                calls.borrow_mut().push("attached");
                Ok(())
            },
            || {
                calls.borrow_mut().push("managed");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls.into_inner(), ["managed", "attached"]);

        let error =
            install_claude_components(|| Ok(()), || Err(anyhow!("synthetic managed failure")))
                .unwrap_err();
        assert!(error.to_string().contains("read-only hooks are installed"));
    }

    #[test]
    fn attached_pin_miss_is_a_skip_note_on_success_not_a_failure() {
        // The real machine this still applies to: Claude crossed a *minor* boundary, which the
        // range rule keeps refusing, while the managed runtime — the thing the Agents tab needs
        // — installed fine. That must succeed, name the reason, and state the one consequence.
        let message = install_claude_components(
            || {
                Err(anyhow!(
                    "Claude Code 2.2.4 is installed, but this Ciao build supports 2.1.222 and later patches of that same minor"
                ))
            },
            || Ok(()),
        )
        .unwrap();
        assert!(message.contains("Managed Claude runtime installed"));
        assert!(message.contains("2.2.4"));
        assert!(message.contains("won't appear in the app"));

        let error = install_claude_components(
            || Err(anyhow!("synthetic attached failure")),
            || Err(anyhow!("synthetic managed failure")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("neither Claude component"));
    }

    #[test]
    fn a_codex_pin_miss_is_a_skip_note_not_a_red_line() {
        // The launch-list item this closes: a Codex that had auto-updated printed
        // "✗ codex integrations not installed" during setup. Accurate and useless — it reads as
        // "Ciao is broken" for a host where everything else installed fine, and a Codex user
        // would see it on ~every setup, since Codex auto-updates the way Claude does.
        let note = codex_pin_miss_note(&anyhow!(
            "Codex 0.148.0 is installed, but this Ciao build supports 0.147.0 and later patches of that same minor"
        ));
        assert!(note.starts_with("○ "), "a skip glyph, not a failure glyph");
        assert!(note.contains("0.148.0"), "names the version it found");
        assert!(
            note.contains("won't appear in the app"),
            "states the one consequence"
        );
        // Codex has no second surface, so this must not borrow Claude's "everything the Agents
        // tab starts will" reassurance — there is nothing here that still works.
        assert!(!note.contains("Agents tab"));
        assert!(
            !note.contains("not installed"),
            "the old red line's wording must not come back"
        );
    }

    #[test]
    fn one_claude_status_names_both_component_states() {
        let status = format_claude_status("installed", "installed but unusable: fixture");
        assert!(status.contains("Attached hooks (read-only"));
        assert!(status.contains("Managed runtime (headless"));
        assert!(status.contains("installed but unusable: fixture"));
    }

    #[test]
    fn one_claude_uninstall_removes_whichever_components_exist() {
        let calls = RefCell::new(Vec::new());
        let removed = uninstall_claude_components(
            || {
                calls.borrow_mut().push("attached");
                Ok(false)
            },
            || {
                calls.borrow_mut().push("managed");
                Ok(true)
            },
        )
        .unwrap();
        assert!(removed);
        assert_eq!(calls.into_inner(), ["managed", "attached"]);

        let error =
            uninstall_claude_components(|| Err(anyhow!("synthetic attached failure")), || Ok(true))
                .unwrap_err();
        assert!(error.to_string().contains("managed runtime was removed"));
    }
}
