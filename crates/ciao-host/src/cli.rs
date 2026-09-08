use std::{
    io::{self, IsTerminal, Write},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use tokio::time::{Instant, sleep};

use std::path::PathBuf;

use crate::{
    agent_integration::AgentIntegration,
    claude_integration::installed_claude_version,
    codex_integration::installed_codex_version,
    daemon,
    identity::{create_or_load_identity, load_identity},
    install::{
        ProgressLine, Spinner, decode_sha256_hex, fetch_archive, fetch_release_file,
        parse_manifest, read_verified_archive, refuse_if_active_work, restore_previous,
        stable_binary_path, stage_and_swap, swap_with_previous, valid_release_version,
    },
    ipc,
    ipc::{
        DaemonStatus, request_create_pairing, request_pairing_status, request_status,
        request_unpair,
    },
    pairing::PairingStatus,
    pi_integration::pi_detected,
    qr::render_terminal_qr,
    service::{
        CronReason, LingerStatus, Supervisor, current_executable, describe_supervisor,
        install_service, uninstall_service,
    },
    storage::{CiaoPaths, PairedDeviceStore, validate_endpoint_id},
};

/// The public channel `install.sh` installs from, so `ciao update` continues where the
/// bootstrap installer left off without the operator restating it. `--release-base` overrides it
/// for a self-hosted channel; `ciao install` still has no default origin at all.
pub(crate) const DEFAULT_RELEASE_BASE: &str = "https://ciaooo.app/dist";
const RELEASE_MANIFEST_FILE: &str = "release.json";

const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_ONLINE_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Parser)]
// "this Mac" was wrong the moment Linux hosts existed, and it is the first line anyone reads.
#[command(
    name = "ciao",
    version,
    about = "Pair Ciao on iPhone with this machine"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create or repair the host identity and per-user daemon
    Setup {
        /// Confirm setup without reading standard input
        #[arg(long)]
        yes: bool,
    },
    /// Create a fresh five-minute pairing QR
    Pair,
    /// Show daemon, relay, identity, and pairing status
    Status {
        /// Emit the stable Phase 0 JSON status object
        #[arg(long)]
        json: bool,
    },
    /// List paired devices, or revoke one
    Unpair {
        /// Device ID from the list; a unique prefix is enough
        device: Option<String>,
    },
    /// Install, update, or roll back the versioned host binary
    Install {
        /// Exact release version to install (for example 0.2.0)
        #[arg(long)]
        version: Option<String>,
        /// Local release archive (ciao-<version>-<target>.tar)
        #[arg(long)]
        archive: Option<PathBuf>,
        /// Owner-configured HTTPS release base to download from
        #[arg(long)]
        release_base: Option<String>,
        /// Declared SHA-256 of the archive (64 hex characters)
        #[arg(long)]
        sha256: Option<String>,
        /// Release manifest file declaring artifact digests
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Restore the previous installed version instead of installing
        #[arg(long)]
        rollback: bool,
    },
    /// Update to the newest version the release channel offers
    #[command(alias = "upgrade")]
    Update {
        /// HTTPS release base to read the manifest from, for a self-hosted channel
        #[arg(long)]
        release_base: Option<String>,
    },
    /// Manage agent integrations and Ciao-managed sessions
    Agent {
        #[command(subcommand)]
        action: AgentCommand,
    },
    /// Show what installed agents sent that this build did not recognize
    Drift {
        /// Emit the ledger as JSON, for handing to a fix session verbatim
        #[arg(long)]
        json: bool,
    },
    /// Stop the service and fully reset this host's Ciao identity and pairing
    Reset {
        /// Confirm the destructive reset without reading standard input
        #[arg(long)]
        yes: bool,
    },
    /// Run the foreground daemon (used by the per-user service)
    #[command(hide = true)]
    Daemon,
    /// Receive one Ciao-owned Claude command-hook event
    #[command(name = "__claude-hook", hide = true)]
    ClaudeHook,
    /// Receive one Ciao-owned Codex command-hook event
    ///
    /// The name and argument are frozen: Codex takes its hook trust hash over the command
    /// string, so renaming this re-gates every Ciao hook behind an interactive review.
    #[command(name = "__codex-hook", hide = true)]
    CodexHook,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Install or update one explicit agent integration
    Install {
        #[arg(value_enum)]
        integration: AgentIntegration,
    },
    /// Remove one explicit agent integration
    Uninstall {
        #[arg(value_enum)]
        integration: AgentIntegration,
    },
    /// Show the state of one explicit agent integration
    Status {
        #[arg(value_enum)]
        integration: AgentIntegration,
    },
    /// List Ciao-managed agent sessions
    Sessions,
    /// Start a Ciao-managed session in a workspace directory (default: current directory)
    Start {
        /// Workspace directory for the managed session
        path: Option<PathBuf>,
    },
    /// Stop a live Ciao-managed session; it remains stored and resumable
    Stop {
        /// Managed session ID from `ciao agent sessions`
        session_id: String,
    },
    /// Forget a stored Ciao-managed session; the conversation stays resumable in Claude
    Forget {
        /// Managed session ID from `ciao agent sessions`
        session_id: String,
    },
    /// Resume a stored Ciao-managed session
    Resume {
        /// Managed session ID from `ciao agent sessions`
        session_id: String,
    },
    /// Adopt a read-only attached Claude session so you can message it from Ciao
    Promote {
        /// Attached session ID from `ciao agent sessions`
        session_id: String,
    },
    /// Hand a Ciao-managed session back to your own Claude and stop managing it
    Release {
        /// Managed session ID from `ciao agent sessions`
        session_id: String,
    },
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    let paths = CiaoPaths::discover()?;
    match cli.command {
        Some(Command::Setup { yes }) => setup_command(&paths, yes).await,
        Some(Command::Pair) => pair_command(&paths).await,
        Some(Command::Status { json }) => status_command(&paths, json, true).await,
        Some(Command::Unpair { device }) => unpair_command(&paths, device).await,
        Some(Command::Install {
            version,
            archive,
            release_base,
            sha256,
            manifest,
            rollback,
        }) => {
            install_command(
                &paths,
                InstallArguments {
                    version,
                    archive,
                    release_base,
                    sha256,
                    manifest,
                    rollback,
                },
            )
            .await
        }
        Some(Command::Update { release_base }) => update_command(&paths, release_base).await,
        Some(Command::Agent { action }) => agent_command(&paths, action).await,
        Some(Command::Drift { json }) => drift_command(&paths, json),
        Some(Command::Reset { yes }) => reset_command(&paths, yes).await,
        Some(Command::Daemon) => daemon::run(paths).await,
        Some(Command::ClaudeHook) => {
            // Observation hooks must fail open and remain silent so a local Ciao outage cannot
            // alter or add noise to the attached Claude terminal session.
            let _ = crate::claude_hook::run(&paths).await;
            Ok(())
        }
        Some(Command::CodexHook) => {
            // Same contract as the Claude hook: silent and fail-open, so a local Ciao outage
            // cannot alter or add noise to the attached Codex terminal session.
            let _ = crate::codex_hook::run(&paths).await;
            Ok(())
        }
        None => default_command(&paths).await,
    }
}

/// Prints the drift ledger the daemon keeps (Spec 017 §4.2). Reads the persisted file rather
/// than asking the daemon: new signatures are flushed the moment they are seen, so the file is
/// at most one count-refresh behind, and a diagnostics read must keep working when the daemon
/// is the thing being diagnosed.
fn drift_command(paths: &CiaoPaths, json: bool) -> Result<()> {
    let ledger = crate::drift::load(&paths.run_dir.join(crate::drift::LEDGER_FILE_NAME))
        .unwrap_or_else(crate::drift::empty_ledger);
    if json {
        println!("{}", serde_json::to_string_pretty(&ledger)?);
    } else {
        println!("{}", crate::drift::render(&ledger));
    }
    Ok(())
}

async fn agent_command(paths: &CiaoPaths, action: AgentCommand) -> Result<()> {
    let message = match action {
        AgentCommand::Install { integration } => integration.install(paths).await?,
        AgentCommand::Uninstall { integration } => integration.uninstall(paths).await?,
        AgentCommand::Status { integration } => integration.status(paths).await?,
        AgentCommand::Sessions => {
            let rows = ipc::request_agent_sessions(&paths.socket_file)
                .await
                .context(
                    "The Ciao daemon is not reachable. Run `ciao setup` or check `ciao status`.",
                )?;
            if rows.is_empty() {
                "No agent sessions. Start one with `ciao agent start`.".into()
            } else {
                rows.iter()
                    .map(|row| {
                        let detail = match row.stored_reason.as_deref() {
                            Some(reason) => format!("{} ({reason})", row.presence),
                            None => row.presence.clone(),
                        };
                        format!(
                            "{}  {}  {}  gen {}  {}",
                            row.session_id,
                            row.topology,
                            detail,
                            row.process_generation,
                            row.workspace_label
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
        AgentCommand::Start { path } => {
            let workspace = match path {
                Some(path) => path,
                None => std::env::current_dir().context("resolve the current directory")?,
            };
            let workspace = workspace
                .canonicalize()
                .context("the workspace directory does not exist")?;
            let outcome =
                ipc::request_agent_start(&paths.socket_file, &workspace.to_string_lossy()).await?;
            lifecycle_message("start", &outcome)
        }
        AgentCommand::Stop { session_id } => {
            // The stop is fenced against the session's current generation so a
            // raced resume cannot be stopped blindly.
            let rows = ipc::request_agent_sessions(&paths.socket_file).await?;
            let Some(row) = rows.iter().find(|row| row.session_id == session_id) else {
                bail!("No managed session with that ID. See `ciao agent sessions`.");
            };
            let outcome =
                ipc::request_agent_stop(&paths.socket_file, &session_id, row.process_generation)
                    .await?;
            lifecycle_message("stop", &outcome)
        }
        AgentCommand::Resume { session_id } => {
            let outcome = ipc::request_agent_resume(&paths.socket_file, &session_id).await?;
            lifecycle_message("resume", &outcome)
        }
        AgentCommand::Forget { session_id } => {
            let outcome = ipc::request_agent_forget(&paths.socket_file, &session_id).await?;
            match (outcome.state.as_str(), outcome.reason_code.as_deref()) {
                // Says what was and was not given up, because the word "forget" does not
                // distinguish them and the conversation surviving is the whole point.
                ("accepted", _) =>
                    "Forgotten. Ciao dropped its record of that session; the conversation itself is untouched and still resumable with `claude --resume`.".into(),
                (_, Some("already_live")) =>
                    "That session is running. Stop it first with `ciao agent stop`, then forget it.".into(),
                (_, Some("unknown_session")) =>
                    "No managed session with that ID. See `ciao agent sessions`.".into(),
                _ => lifecycle_message("forget", &outcome),
            }
        }
        AgentCommand::Promote { session_id } => {
            let outcome = ipc::request_agent_promote(&paths.socket_file, &session_id).await?;
            match (outcome.state.as_str(), outcome.reason_code.as_deref()) {
                ("accepted", _) => format!(
                    "Taken over. Ciao ended the terminal session and resumed that conversation as a managed one{}, so you can message it from your phone.",
                    outcome
                        .session_id
                        .as_deref()
                        .map(|id| format!(": {id}"))
                        .unwrap_or_default()
                ),
                (_, Some("terminal_owner_live")) =>
                    "That Claude did not exit when asked, so Ciao stopped rather than become a second writer on the same conversation. Quit it and try again.".into(),
                (_, Some("no_vendor_session")) =>
                    "That session has not taken a turn yet, so there is nothing for Ciao to resume. Send it a prompt in the terminal first.".into(),
                (_, Some("promotion_unsupported")) =>
                    "Only attached Claude sessions need promoting. Pi already accepts messages from Ciao.".into(),
                (_, Some("workspace_path_unknown")) =>
                    "Ciao does not know where that session is running, so it cannot start a worker there. Reconnect it under a current Ciao host.".into(),
                _ => lifecycle_message("promote", &outcome),
            }
        }
        AgentCommand::Release { session_id } => {
            let outcome = ipc::request_agent_release(&paths.socket_file, &session_id).await?;
            match (
                outcome.state.as_str(),
                outcome.vendor_session_id.as_deref(),
                outcome.handback_session.as_deref(),
            ) {
                // Where it is, not what to type. The command stays as a second line because a
                // terminal session can be closed, and then the ID is the only way back.
                ("accepted", Some(vendor), Some(session)) => format!(
                    "Released into a terminal session. Attach it from Ciao, or here:\n\n  tmux attach -t ={session}\n\nIf that session is gone, the conversation is still yours:\n\n  claude --resume {vendor}\n\nCiao has stopped managing it and will not resume it again."
                ),
                ("accepted", Some(vendor), None) => format!(
                    "Released, but no terminal session could be started for it. This session is still yours to continue in Claude:\n\n  claude --resume {vendor}\n\nCiao has stopped managing it and will not resume it again."
                ),
                ("accepted", None, _) => "Released.".into(),
                _ => lifecycle_message("release", &outcome),
            }
        }
    };
    println!("{message}");
    Ok(())
}

fn lifecycle_message(verb: &str, outcome: &ipc::LifecycleResult) -> String {
    if outcome.state == "accepted" {
        match (&outcome.session_id, outcome.process_generation) {
            (Some(session_id), Some(generation)) => {
                format!("Managed {verb} accepted: {session_id} (generation {generation})")
            }
            (Some(session_id), None) => format!("Managed {verb} accepted: {session_id}"),
            _ => format!("Managed {verb} accepted"),
        }
    } else {
        let reason = outcome.reason_code.as_deref().unwrap_or("unknown_reason");
        format!("Managed {verb} refused: {reason}")
    }
}

async fn default_command(paths: &CiaoPaths) -> Result<()> {
    match load_identity(paths) {
        // An identity alone does not mean this host is set up: setup may have created one and
        // then failed to install a supervisor, which is exactly the state a host with no
        // per-user systemd manager was left in. Reporting that as status describes the problem
        // instead of fixing it, so repair the service when nothing is answering. Setup is
        // idempotent and preserves the existing identity.
        Ok(Some(_)) => {
            if request_status(&paths.socket_file).await.is_ok() {
                status_command(paths, false, false).await
            } else {
                setup_command(paths, true).await
            }
        }
        Ok(None) => {
            if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                bail!(
                    "Ciao is not set up and this invocation is non-interactive. Run `ciao setup --yes`."
                );
            }
            if prompt_for_setup()? {
                setup_command(paths, true).await
            } else {
                Ok(())
            }
        }
        Err(error) => Err(error).context("Ciao configuration is invalid"),
    }
}

fn prompt_for_setup() -> Result<bool> {
    loop {
        print!("\nCiao is not set up. Set it up now? [Y/n] ");
        io::stdout().flush()?;
        let mut answer = String::new();
        let read = io::stdin().read_line(&mut answer)?;
        if read == 0 {
            println!();
            return Ok(false);
        }
        match parse_setup_answer(&answer) {
            Some(proceed) => return Ok(proceed),
            None => continue,
        }
    }
}

fn parse_setup_answer(answer: &str) -> Option<bool> {
    match answer.trim() {
        "" | "y" | "Y" => Some(true),
        "n" | "N" => Some(false),
        _ => None,
    }
}

/// Vendor presence, not integration state: the pre-selection a person confirms or edits. A
/// probe that errors reads as absent — the picker still accepts that name typed explicitly.
fn detect_agents(paths: &CiaoPaths) -> Vec<AgentIntegration> {
    let mut detected = Vec::new();
    if installed_claude_version(paths).ok().flatten().is_some() {
        detected.push(AgentIntegration::Claude);
    }
    if installed_codex_version(paths).ok().flatten().is_some() {
        detected.push(AgentIntegration::Codex);
    }
    if pi_detected(paths) {
        detected.push(AgentIntegration::Pi);
    }
    detected
}

fn integration_list(integrations: &[AgentIntegration]) -> String {
    integrations
        .iter()
        .map(|integration| integration.cli_name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The setup step that makes the Agents tab work on this host. Installer trouble prints and
/// never aborts setup — pairing must still happen on a host whose npm is briefly unhappy.
async fn install_agent_integrations(paths: &CiaoPaths, yes: bool) -> Result<()> {
    println!();
    let detected = detect_agents(paths);
    if detected.is_empty() {
        println!("No agent CLIs detected on this host (looked for claude, codex, and pi).");
        println!("The Agents tab needs one. Install an agent, then run `ciao setup` again.");
        return Ok(());
    }
    let missing: Vec<AgentIntegration> = [
        AgentIntegration::Claude,
        AgentIntegration::Codex,
        AgentIntegration::Pi,
    ]
    .into_iter()
    .filter(|integration| !detected.contains(integration))
    .collect();
    if missing.is_empty() {
        println!("Detected agents: {}.", integration_list(&detected));
    } else {
        println!(
            "Detected agents: {} ({} not found).",
            integration_list(&detected),
            integration_list(&missing)
        );
    }
    let selected = if !yes && io::stdin().is_terminal() && io::stdout().is_terminal() {
        prompt_for_agent_selection(&detected)?
    } else {
        println!("Installing integrations for the detected agents.");
        detected
    };
    for integration in selected {
        println!();
        match integration.install(paths).await {
            Ok(message) => println!("{message}"),
            Err(error) => println!(
                "✗ {} integrations not installed: {error:#}",
                integration.cli_name()
            ),
        }
    }
    Ok(())
}

fn prompt_for_agent_selection(detected: &[AgentIntegration]) -> Result<Vec<AgentIntegration>> {
    loop {
        print!(
            "Install integrations for {}? Press Enter, or type a different list (claude codex pi, or none): ",
            integration_list(detected)
        );
        io::stdout().flush()?;
        let mut answer = String::new();
        let read = io::stdin().read_line(&mut answer)?;
        if read == 0 {
            println!();
            return Ok(Vec::new());
        }
        match parse_agent_selection(&answer, detected) {
            Some(selection) => return Ok(selection),
            None => continue,
        }
    }
}

fn parse_agent_selection(
    answer: &str,
    detected: &[AgentIntegration],
) -> Option<Vec<AgentIntegration>> {
    let trimmed = answer.trim();
    match trimmed {
        "" | "y" | "Y" | "yes" => return Some(detected.to_vec()),
        "n" | "N" | "no" | "none" => return Some(Vec::new()),
        _ => {}
    }
    let mut selection = Vec::new();
    for token in trimmed
        .split([' ', ',', '\t'])
        .filter(|token| !token.is_empty())
    {
        let integration = match token.to_ascii_lowercase().as_str() {
            "claude" => AgentIntegration::Claude,
            "codex" => AgentIntegration::Codex,
            "pi" => AgentIntegration::Pi,
            _ => return None,
        };
        if !selection.contains(&integration) {
            selection.push(integration);
        }
    }
    Some(selection)
}

async fn setup_command(paths: &CiaoPaths, yes: bool) -> Result<()> {
    if !setup_ready(paths, yes).await? {
        return Ok(());
    }

    // Integrations are part of setup, not a command to discover later: setup used to end with
    // no next step, and the one verb that made the Agents tab work was named nowhere a person
    // would look. Deliberately in setup and not in `setup_ready`: pair's self-repair stays a
    // fast lane to the QR, while `ciao setup` remains the one complete repair command — which
    // is also why this runs before the already-paired early return below, so "install Node,
    // then run `ciao setup` again" finishes the job on a host that is otherwise healthy.
    install_agent_integrations(paths, yes).await?;

    // Setup is also the documented repair/reload path, and a host that already has paired
    // devices has nothing left to do once the daemon is healthy. Ending every run on a pairing
    // wait meant a reload sat on a QR nobody was going to scan until the code expired — and
    // with output piped, not even the QR was visible to explain why. Pairing another device is
    // what `ciao pair` is for, which is what status has always said here.
    if request_status(&paths.socket_file)
        .await
        .is_ok_and(|status| status.paired_devices > 0)
    {
        println!("\nRun `ciao pair` to pair another device.");
        return Ok(());
    }

    println!();
    create_render_and_wait(paths).await
}

/// Everything setup guarantees before any pairing decision: identity, an installed service,
/// a daemon answering as this binary's version, and the relay online. Returns false when no
/// supervisor could be installed — the printed note already explains the manual
/// `ciao daemon` + `ciao pair` path, so callers just stop.
async fn setup_ready(paths: &CiaoPaths, yes: bool) -> Result<bool> {
    let any_setup_file = paths.credentials_file.exists() || paths.config_file.exists();
    if !any_setup_file && !yes {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            bail!("Setup needs confirmation. Run `ciao setup --yes` non-interactively.");
        }
        if !prompt_for_setup()? {
            return Ok(false);
        }
    }

    print!("Creating host identity… ");
    io::stdout().flush()?;
    let setup = create_or_load_identity(paths)?;
    if setup.repaired_config {
        println!("done (repaired config; identity preserved)");
    } else if setup.created {
        println!("done");
    } else {
        println!("done (existing identity preserved)");
    }

    print!("Installing Ciao daemon… ");
    io::stdout().flush()?;
    let executable = current_executable()?;
    // A host with no supervisor is not a host Ciao cannot run on. Failing here used to abort
    // setup, which told the operator they were blocked when only persistence was unavailable.
    let supervisor = match install_service(paths, &executable) {
        Ok(supervisor) => supervisor,
        Err(error) => {
            println!("skipped");
            print_unsupervised_note(&error);
            return Ok(false);
        }
    };
    // Setup points the service at the binary running it, so that binary's version is what the
    // daemon must come back as.
    wait_for_daemon(
        paths,
        setup.identity.endpoint_id.to_string(),
        env!("CARGO_PKG_VERSION"),
    )
    .await?;
    println!("{}", supervisor_done_label(supervisor));
    print_supervisor_note(supervisor);

    print!("Waiting for Iroh relay… ");
    io::stdout().flush()?;
    wait_for_online(paths).await?;
    println!("done");

    Ok(true)
}

/// Setup keeps the identity it just created and explains the two-command path, so a missing
/// supervisor reads as "no automatic restart" rather than "Ciao does not work here".
fn print_unsupervised_note(reason: &anyhow::Error) {
    println!("\nCiao could not install a supervised background service here:\n\n{reason}\n");
    println!(
        "This does not stop Ciao from working. Your host identity is saved. Start the daemon\nyourself, then pair from another shell:\n\n    ciao daemon\n    ciao pair\n"
    );
    println!(
        "A daemon started that way runs until you stop it and does not come back after a\nreboot. Once the cause above is resolved, rerun `ciao setup --yes` to install the\nsupervised service."
    );
}

/// The setup line already says "done"; this qualifies it when a weaker rung was used, so the
/// operator is never told they have a supervised service they do not have.
fn supervisor_done_label(supervisor: Supervisor) -> &'static str {
    match supervisor {
        Supervisor::Launchd | Supervisor::SystemdUser { .. } => "done",
        Supervisor::CronReboot {
            reason: CronReason::NoUserManager,
        } => "done (boot task — this host has no user service manager)",
        Supervisor::CronReboot {
            reason: CronReason::LingeringDisabled,
        } => "done (boot task — a user service would not survive logout here)",
    }
}

fn print_supervisor_note(supervisor: Supervisor) {
    match supervisor {
        Supervisor::Launchd => {}
        Supervisor::SystemdUser { linger } => print_linger_note(linger),
        // Cron starts the daemon at boot but never restarts it, so say so rather than let
        // "done" imply the same guarantees systemd gives. The two reasons are not
        // interchangeable: one host lacks a manager, the other has one that would stop at
        // logout, and telling an operator the wrong one sends them to fix the wrong thing.
        Supervisor::CronReboot {
            reason: CronReason::NoUserManager,
        } => println!(
            "\nNote: this host has no per-user systemd manager, so Ciao starts from a `@reboot`\ncrontab entry. It comes back after a reboot, but is not restarted if it stops\nunexpectedly. `ciao reset` removes the entry.\n"
        ),
        Supervisor::CronReboot {
            reason: CronReason::LingeringDisabled,
        } => println!(
            "\nNote: lingering is disabled for this account, so a systemd user service would stop\nwhen you log out and would not start at boot. Ciao uses a `@reboot` crontab entry\ninstead, which survives both. It is not restarted if it stops unexpectedly; enabling\nlingering with `loginctl enable-linger` and rerunning setup adds that. `ciao reset`\nremoves the entry.\n"
        ),
    }
}

fn print_linger_note(linger: LingerStatus) {
    if linger == LingerStatus::Disabled {
        // Spec 004 §8.2.5: explain the exact consequence and the explicit remedy. Enabling
        // lingering may prompt for authorization; Ciao never invokes sudo itself.
        println!(
            "\nNote: lingering is disabled for this account, so the Ciao service stops when you\nlog out and does not start after a reboot until you log in. To keep it running, run:\n\n    loginctl enable-linger\n"
        );
    }
}

struct InstallArguments {
    version: Option<String>,
    archive: Option<PathBuf>,
    release_base: Option<String>,
    sha256: Option<String>,
    manifest: Option<PathBuf>,
    rollback: bool,
}

/// Spec 004 §9.2: the explicit alpha installer/updater. Verification happens before any
/// replacement; a failed post-install health check restores the previous binary and service.
async fn install_command(paths: &CiaoPaths, arguments: InstallArguments) -> Result<()> {
    let target = crate::install::current_release_target()
        .ok_or_else(|| anyhow!("this OS/architecture has no released Ciao artifact"))?;

    // Never interrupt an active terminal silently. An unreachable daemon means no terminal.
    let active = request_status(&paths.socket_file).await.ok();
    refuse_if_active_work(
        active.as_ref().and_then(|status| status.active_terminals),
        active
            .as_ref()
            .and_then(|status| status.resumable_terminals),
    )?;
    announce_resumable_terminals(active.as_ref());

    if arguments.rollback {
        if arguments.version.is_some()
            || arguments.archive.is_some()
            || arguments.release_base.is_some()
            || arguments.sha256.is_some()
            || arguments.manifest.is_some()
        {
            bail!("--rollback takes no other installer options");
        }
        println!("Rolling back to the previous Ciao version…");
        let chats = ManagedChatsToRestore::capture(paths).await;
        chats.announce();
        swap_with_previous(paths)?;
        if let Err(error) = setup_service_and_check_health(paths, None).await {
            // Failed rollback: put the newer binary back so the host is not left on a
            // version that just failed its health check.
            let _ = swap_with_previous(paths);
            let _ = setup_service_and_check_health(paths, None).await;
            chats.restore().await;
            return Err(error.context("rollback failed; the newer version was restored"));
        }
        chats.restore().await;
        println!("Rollback complete.");
        return Ok(());
    }

    let version = arguments
        .version
        .ok_or_else(|| anyhow!("provide --version (or --rollback)"))?;
    if !valid_release_version(&version) {
        bail!("--version is not a valid release version");
    }

    // Declared digest: an explicit --sha256 or a bounded release manifest. The manifest also
    // carries the archive's exact size, which is what lets the download show a real percentage
    // rather than a running byte count.
    let (expected_sha256, expected_bytes) = match (&arguments.sha256, &arguments.manifest) {
        (Some(hex), _) => (
            decode_sha256_hex(hex)
                .ok_or_else(|| anyhow!("--sha256 must be 64 hexadecimal characters"))?,
            None,
        ),
        (None, Some(manifest_path)) => {
            let bytes = std::fs::read(manifest_path)
                .with_context(|| format!("read manifest {}", manifest_path.display()))?;
            let manifest = parse_manifest(&bytes)?;
            let artifact = manifest
                .artifacts
                .iter()
                .find(|artifact| artifact.version == version && artifact.target == target)
                .ok_or_else(|| anyhow!("the manifest has no artifact for {version} on {target}"))?;
            (
                decode_sha256_hex(&artifact.sha256)
                    .ok_or_else(|| anyhow!("the manifest digest is malformed"))?,
                Some(artifact.bytes),
            )
        }
        (None, None) => bail!("provide --sha256 or --manifest to declare the archive digest"),
    };

    // Archive source: a local file or an explicit owner-configured HTTPS base.
    let mut downloaded: Option<PathBuf> = None;
    let archive_path = match (&arguments.archive, &arguments.release_base) {
        (Some(path), _) => path.clone(),
        (None, Some(base)) => {
            paths.ensure_layout()?;
            let destination = paths
                .state_dir
                .join(format!(".ciao-download.{}.tar", std::process::id()));
            print!("Downloading Ciao {version}… ");
            io::stdout().flush()?;
            // With only `--sha256` the size is unknown and nothing is drawn, rather than a
            // percentage invented from a total nobody declared.
            fetch_archive(base, &version, target, &destination, expected_bytes).inspect_err(
                |_| {
                    println!();
                },
            )?;
            println!("done");
            downloaded = Some(destination.clone());
            destination
        }
        (None, None) => bail!("provide --archive or --release-base"),
    };

    let result = run_verified_install(paths, &archive_path, &version, &expected_sha256).await;
    if let Some(downloaded) = downloaded {
        let _ = std::fs::remove_file(downloaded);
    }
    result
}

/// Updates to whatever version the channel currently advertises.
///
/// The convenience counterpart to `install`, and it makes a different trade deliberately: here
/// the channel names the version and the digest, where `install` requires the operator to
/// declare both so a compromised origin cannot choose for them. That is the trust `install.sh`
/// already takes when it reads the manifest and verifies the published sidecar, so the update
/// path is exactly as strong as the install path that preceded it — and never weaker than the
/// binary already on disk, because the archive is still verified against a declared digest and
/// the previous version is still preserved for rollback.
/// ` (cb4abbec84, 6941982a89)` for the devices holding terminals open, or nothing at all when
/// there are none or the daemon is too old to say. Printed beside the count because the count
/// alone cannot answer the only question anyone asks of it: which one is that?
fn terminal_devices(status: &DaemonStatus) -> String {
    match status.active_terminal_devices.as_deref() {
        Some([]) | None => String::new(),
        Some(devices) => format!(" ({})", devices.join(", ")),
    }
}

/// Exactly the sessions the restart will take down and this run can start again: Ciao's own
/// workers, currently live. An attached session runs in the operator's own terminal and Ciao
/// only observes it — a restart does not stop it and resuming it is not Ciao's to do. A stored
/// session was already not running, and starting one nobody asked for is not restoration.
fn live_managed_ids(rows: Vec<ipc::ManagedSessionRow>) -> Vec<String> {
    rows.into_iter()
        .filter(|row| row.topology == "managed" && row.presence == "live")
        .map(|row| row.session_id)
        .collect()
}

/// The managed chats a restart is about to demote, so the same run can put them back.
///
/// A starting daemon stores every record still marked live with the reason `daemon_restart`: the
/// conversation keeps its history and comes back on command. That is what makes an update
/// recoverable rather than destructive, and why the installer no longer refuses over one. The
/// exception no design closes is a reply being generated at that moment — it dies with its
/// worker — so the intent is said out loud before anything moves.
struct ManagedChatsToRestore {
    socket: PathBuf,
    session_ids: Vec<String>,
}

impl ManagedChatsToRestore {
    /// An unreachable daemon has nothing live, and a listing this build cannot read is not
    /// evidence that it does. Either way there is nothing to put back.
    async fn capture(paths: &CiaoPaths) -> Self {
        let session_ids = live_managed_ids(
            ipc::request_agent_sessions(&paths.socket_file)
                .await
                .unwrap_or_default(),
        );
        Self {
            socket: paths.socket_file.clone(),
            session_ids,
        }
    }

    fn announce(&self) {
        if !self.session_ids.is_empty() {
            println!(
                "{} managed chat(s) are live. The restart stops them and this run resumes them with their history; a reply being written right now is lost.",
                self.session_ids.len()
            );
        }
    }

    /// Runs after the daemon is healthy again, on the failed path too: a rollback restarts the
    /// daemon exactly as an install does, so the chats were demoted either way. A resume that
    /// refuses is reported and skipped — the update is done, and the app can still resume it.
    async fn restore(self) {
        let mut resumed = 0;
        for session_id in &self.session_ids {
            match ipc::request_agent_resume(&self.socket, session_id).await {
                Ok(outcome) if outcome.state == "accepted" => resumed += 1,
                Ok(outcome) => println!(
                    "Could not resume {session_id}: {}. Resume it from the app.",
                    outcome.reason_code.as_deref().unwrap_or("unknown_reason")
                ),
                Err(error) => {
                    println!("Could not resume {session_id}: {error}. Resume it from the app.")
                }
            }
        }
        if resumed > 0 {
            println!("Resumed {resumed} managed chat(s).");
        }
    }
}

/// Says once what is about to happen to the terminals the installer just declined to refuse on.
/// The view goes away for a few seconds and comes back on the same session — that is the whole
/// promise, and unannounced it reads as the update having killed something.
fn announce_resumable_terminals(status: Option<&DaemonStatus>) {
    let resumable = status
        .and_then(|status| status.resumable_terminals)
        .unwrap_or(0);
    if resumable > 0 {
        println!(
            "{resumable} terminal(s) are attached to tmux or Herdr sessions. The restart closes the view; the sessions keep running and the app reattaches."
        );
    }
}

/// The artifact this host should move to, or `None` when it is already there.
///
/// First match wins, exactly as `install.sh` resolves a version, so the two entry points never
/// disagree about which release is current. Pure, so the decision is checkable without a
/// network or a service.
fn update_artifact<'a>(
    manifest: &'a crate::install::ReleaseManifest,
    target: &str,
    current: &str,
) -> Result<Option<&'a crate::install::ReleaseArtifact>> {
    let artifact = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.target == target)
        .ok_or_else(|| anyhow!("the release channel has no artifact for {target}"))?;
    Ok((artifact.version != current).then_some(artifact))
}

async fn update_command(paths: &CiaoPaths, release_base: Option<String>) -> Result<()> {
    let base = release_base.unwrap_or_else(|| DEFAULT_RELEASE_BASE.to_owned());
    let target = crate::install::current_release_target()
        .ok_or_else(|| anyhow!("this OS/architecture has no released Ciao artifact"))?;

    // Same refusal as install: never swap the binary under a live terminal or managed worker.
    let status = request_status(&paths.socket_file).await.ok();
    refuse_if_active_work(
        status.as_ref().and_then(|status| status.active_terminals),
        status
            .as_ref()
            .and_then(|status| status.resumable_terminals),
    )?;
    announce_resumable_terminals(status.as_ref());

    paths.ensure_layout()?;
    let manifest_path = paths
        .state_dir
        .join(format!(".ciao-manifest.{}.json", std::process::id()));
    let manifest = match fetch_release_file(&base, RELEASE_MANIFEST_FILE, &manifest_path, None) {
        Ok(()) => std::fs::read(&manifest_path)
            .context("read downloaded release manifest")
            .and_then(|bytes| parse_manifest(&bytes)),
        Err(error) => Err(error),
    };
    let _ = std::fs::remove_file(&manifest_path);
    let manifest = manifest?;

    // The daemon is what serves the phone, so its version is what "installed" means — not this
    // process's. The bootstrap installer replaces the binary without restarting the service, so
    // the CLI is already current while the daemon still runs the old code; comparing against
    // this process would report success and leave the stale daemon exactly where it was. Falls
    // back to this binary's version only when no daemon answers, which is the best available
    // answer for a host that is not running one.
    let current = status
        .as_ref()
        .and_then(|status| status.version.as_deref())
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let Some(artifact) = update_artifact(&manifest, target, current)? else {
        println!("Ciao {current} is already the newest release.");
        return Ok(());
    };
    let expected_sha256 = decode_sha256_hex(&artifact.sha256)
        .ok_or_else(|| anyhow!("the manifest digest is malformed"))?;

    println!("Updating Ciao {current} → {}…", artifact.version);
    // Said once, plainly. The update restarts the daemon, so a phone loses its connection for a
    // few seconds and attached sessions vanish from the directory until their next event. That
    // is not a failure, but it looks like one to anyone who was not told.
    if status
        .as_ref()
        .and_then(|status| status.active_agent_sessions)
        .unwrap_or(0)
        > 0
    {
        println!(
            "The daemon restarts; attached sessions reconnect on their own and their agents keep running."
        );
    }
    let destination = paths
        .state_dir
        .join(format!(".ciao-download.{}.tar", std::process::id()));
    print!("Downloading Ciao {}… ", artifact.version);
    io::stdout().flush()?;
    let result = match fetch_archive(
        &base,
        &artifact.version,
        target,
        &destination,
        Some(artifact.bytes),
    ) {
        Ok(()) => {
            println!("done");
            run_verified_install(paths, &destination, &artifact.version, &expected_sha256).await
        }
        Err(error) => {
            println!();
            Err(error)
        }
    };
    let _ = std::fs::remove_file(&destination);
    result
}

async fn run_verified_install(
    paths: &CiaoPaths,
    archive_path: &std::path::Path,
    version: &str,
    expected_sha256: &[u8; 32],
) -> Result<()> {
    let entries = spinning("Verifying archive", || {
        read_verified_archive(archive_path, version, expected_sha256)
    })?;
    // Captured after verification, because a bad archive never restarts anything, and before the
    // swap, because that is the last moment the old daemon can still be asked what was live.
    let chats = ManagedChatsToRestore::capture(paths).await;
    chats.announce();
    let had_previous = spinning(&format!("Installing Ciao {version}"), || {
        stage_and_swap(paths, &entries, Some(version))
    })?;

    let result = match setup_service_and_check_health(paths, Some(version)).await {
        Ok(()) => {
            println!(
                "Ciao {version} is installed at {} and healthy.",
                stable_binary_path(paths).display()
            );
            Ok(())
        }
        Err(error) if had_previous => {
            // Spec 004 §9.2.8: restore the previous binary and service on health failure.
            restore_previous(paths)?;
            let restore = setup_service_and_check_health(paths, None).await;
            match restore {
                Ok(()) => Err(error.context(
                    "the new version failed its health check; the previous version was restored",
                )),
                Err(restore_error) => Err(error.context(restore_error).context(
                    "the new version failed its health check and the restore also failed",
                )),
            }
        }
        Err(error) => Err(error.context(
            "the fresh install failed its health check; no previous version exists to restore",
        )),
    };
    // Both arms above have restarted the daemon — the failing one twice, into the previous
    // version — so the chats it demoted are put back whichever version ended up running.
    chats.restore().await;
    result
}

/// `Verifying archive… ⠹` → `Verifying archive… done`. The same line the download draws, for the
/// steps after it: each one takes seconds of its own, and a label with nothing moving under it
/// is indistinguishable from a hang.
fn spinning<T>(label: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
    print!("{label}… ");
    let _ = io::stdout().flush();
    let outcome = {
        let _spinner = Spinner::start();
        work()
    };
    // Either way the line is closed here, so the error that follows a failure starts at column
    // zero rather than after a half-written label.
    match &outcome {
        Ok(_) => println!("done"),
        Err(_) => println!(),
    }
    outcome
}

/// Runs the accepted idempotent setup routines against the stable binary path, then requires
/// authenticated local health within 15 seconds (Spec 004 §15): daemon reachable, identity
/// unchanged, and — when given — the expected version running.
async fn setup_service_and_check_health(
    paths: &CiaoPaths,
    expected_version: Option<&str>,
) -> Result<()> {
    // Bootstrapping the service is the slowest step in an update on macOS — launchctl, then a
    // fresh binary meeting Gatekeeper for the first time — and it used to run under a line that
    // had already said everything it was going to say.
    let (setup, supervisor) = spinning("Starting the Ciao service", || {
        let setup = create_or_load_identity(paths)?;
        let supervisor = install_service(paths, &stable_binary_path(paths))?;
        Ok((setup, supervisor))
    })?;
    let expected_endpoint = setup.identity.endpoint_id.to_string();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut waiting = ProgressLine::new(true);
    loop {
        // What this attempt actually got. One timeout used to cover a daemon that never
        // started, one running the wrong version, and one whose reply this CLI could not parse
        // — three problems with three different fixes, reported identically and pointing at a
        // log that only the first of them ever writes to.
        let refused = match request_status(&paths.socket_file).await {
            Ok(status) => {
                if status.daemon == "running"
                    && status.host_endpoint_id == expected_endpoint
                    && expected_version
                        .is_none_or(|version| status.version.as_deref() == Some(version))
                {
                    waiting.clear();
                    print_supervisor_note(supervisor);
                    return Ok(());
                }
                match expected_version {
                    Some(version) if status.version.as_deref() != Some(version) => format!(
                        "it answered as version {}, not {version}",
                        status.version.as_deref().unwrap_or("unknown")
                    ),
                    _ if status.host_endpoint_id != expected_endpoint => {
                        "it answered for a different host identity".to_string()
                    }
                    _ => format!("it answered but reported daemon {}", status.daemon),
                }
            }
            // A reply this CLI cannot decode is the upgrade-shaped failure: `ciao update` runs
            // the old CLI against the new daemon, so a field the old build has never heard of
            // arrives here. Saying so is what turns a silent 15-second wall into a diagnosis.
            Err(error) => format!("its reply could not be read ({error})"),
        };
        if Instant::now() >= deadline {
            waiting.clear();
            bail!(
                "the daemon did not become healthy within 15 seconds: {refused}. Inspect {}.",
                paths.log_hint()
            );
        }
        waiting.draw("");
        sleep(Duration::from_millis(250)).await;
    }
}

/// Spec 004 §9.3: explicit destructive full reset/unpair for the alpha host when the phone is
/// unavailable. Stops the service and removes identity, pairing, and configuration; the next
/// `ciao setup` creates a fresh identity requiring a new QR pairing.
async fn reset_command(paths: &CiaoPaths, yes: bool) -> Result<()> {
    if !yes {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            bail!("Reset needs confirmation. Run `ciao reset --yes` non-interactively.");
        }
        println!(
            "This stops the Ciao service and deletes this host's identity, paired devices, and\nconfiguration. Every paired phone will need a new QR pairing."
        );
        print!("Type 'reset' to continue: ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if answer.trim() != "reset" {
            println!("Reset cancelled.");
            return Ok(());
        }
    }

    print!("Stopping Ciao service… ");
    io::stdout().flush()?;
    uninstall_service(paths)?;
    println!("done");

    print!("Removing identity, pairing, and configuration… ");
    io::stdout().flush()?;
    for file in [
        &paths.credentials_file,
        &paths.paired_devices_file,
        &paths.agent_metadata_file,
        &paths.config_file,
        &paths.socket_file,
        &paths.agent_socket_file,
    ] {
        match std::fs::remove_file(file) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("remove {}", file.display()));
            }
        }
    }
    println!("done");
    println!("\nThis host is fully reset. Run `ciao setup --yes` to start again.");
    Ok(())
}

async fn pair_command(paths: &CiaoPaths) -> Result<()> {
    // Every surface teaches `ciao pair` as the one command — the app's Pair screen, the
    // installer's next-step line, every expired/consumed-QR error on the phone — so it must
    // work from any state a newcomer can reach, not bail with the name of a different
    // command. Setup is idempotent and preserves an existing identity; this is the same
    // repair bare `ciao` performs. Without a terminal on stdout the explicit errors remain:
    // a QR needs one anyway, and a script should not grow a service install by surprise.
    let identity = match load_identity(paths)? {
        Some(identity) => identity,
        None => {
            if !io::stdout().is_terminal() {
                bail!("Ciao is not set up. Run `ciao setup --yes` first.");
            }
            println!("Ciao is not set up. Setting it up first.\n");
            if !setup_ready(paths, true).await? {
                return Ok(());
            }
            load_identity(paths)?
                .ok_or_else(|| anyhow!("setup finished but the host identity is missing"))?
        }
    };
    let status = match request_status(&paths.socket_file).await {
        Ok(status) => status,
        Err(_) if io::stdout().is_terminal() => {
            println!("Ciao daemon is not answering; repairing the service first.\n");
            if !setup_ready(paths, true).await? {
                return Ok(());
            }
            request_status(&paths.socket_file).await.with_context(|| {
                format!(
                    "Ciao daemon is still not answering after setup. Inspect {}.",
                    paths.log_hint()
                )
            })?
        }
        // The identity loaded above, so setup has already run. Name the action that actually
        // works here: on a host with no supervisor the daemon is simply not started yet, and
        // telling the operator to go "resolve" something implies they are blocked when the
        // next command would have worked.
        Err(error) => {
            return Err(error).context(
                "Ciao daemon is not running. Start it in another shell with `ciao daemon`, or \
                 rerun `ciao setup --yes` to install a supervised service",
            );
        }
    };
    if status.host_endpoint_id != identity.endpoint_id.to_string() {
        bail!("daemon host identity does not match local configuration");
    }
    if status.iroh != "online" {
        bail!(
            "Iroh is {}. Check {} and retry when the relay is online.",
            status.iroh,
            paths.log_hint()
        );
    }
    create_render_and_wait(paths).await
}

async fn create_render_and_wait(paths: &CiaoPaths) -> Result<()> {
    let offer = request_create_pairing(&paths.socket_file)
        .await
        .context("request a pairing offer from the daemon")?;
    let rendered = render_terminal_qr(&offer.qr_uri)?;
    println!("Scan this QR with Ciao on iPhone:\n");
    println!("{rendered}");
    println!("Waiting for iPhone…");

    loop {
        let now = unix_now()?;
        if now > offer.expires_at.saturating_add(2) {
            bail!("Pairing code expired. Run `ciao pair` again.");
        }
        let result = request_pairing_status(&paths.socket_file, &offer.pairing_id)
            .await
            .context("lost contact with the daemon while waiting for pairing")?;
        let status: PairingStatus =
            serde_json::from_value(result).context("daemon returned malformed pairing status")?;
        match status.state.as_str() {
            "pending" | "accepted" => {}
            "connected" if status.connected => {
                let endpoint = status.installation_endpoint_id.ok_or_else(|| {
                    anyhow!("daemon omitted the connected installation endpoint ID")
                })?;
                validate_endpoint_id(&endpoint)?;
                let short: String = endpoint.chars().take(10).collect();
                println!("✓ Paired and connected: {short}");
                println!("Open the Agents tab on your iPhone and start a session.");
                return Ok(());
            }
            "expired" | "rejected" | "unknown" => {
                bail!(
                    "{}",
                    status.message.unwrap_or_else(|| "Pairing failed.".into())
                );
            }
            _ => bail!("daemon returned an unknown pairing state"),
        }
        tokio::select! {
            () = sleep(POLL_INTERVAL) => {},
            result = tokio::signal::ctrl_c() => {
                result?;
                bail!("Pairing wait cancelled. The code remains valid until it expires or a new code replaces it.");
            }
        }
    }
}

/// Lists paired devices with no argument, revokes one with it.
///
/// Listing reads the file, the same read `status` already falls back to. Revoking goes through
/// the daemon, which holds the store in memory and would overwrite a direct file edit on its
/// next write — so there stays exactly one writer.
async fn unpair_command(paths: &CiaoPaths, device: Option<String>) -> Result<()> {
    let store = PairedDeviceStore::load(&paths.paired_devices_file)?;
    let Some(query) = device else {
        if store.is_empty() {
            println!("No paired devices.");
            return Ok(());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or_default();
        println!("Paired devices:");
        for entry in store.devices() {
            println!(
                "  {}  paired {}",
                &entry.endpoint_id[..10],
                describe_age(now.saturating_sub(entry.paired_at))
            );
        }
        println!("\nRun `ciao unpair <device>` to revoke one.");
        return Ok(());
    };

    let query = query.to_ascii_lowercase();
    if query.is_empty() {
        bail!("Pass a device ID. Run `ciao unpair` to list them.");
    }
    let matches: Vec<&str> = store
        .devices()
        .iter()
        .map(|entry| entry.endpoint_id.as_str())
        .filter(|endpoint_id| endpoint_id.starts_with(&query))
        .collect();
    let endpoint_id = match matches.as_slice() {
        [endpoint_id] => *endpoint_id,
        [] => bail!("No paired device starts with {query}. Run `ciao unpair` to list them."),
        _ => bail!(
            "{} paired devices start with {query}. Use more characters.",
            matches.len()
        ),
    };
    let short = &endpoint_id[..10];

    match request_unpair(&paths.socket_file, endpoint_id).await {
        Ok(true) => {
            println!("Unpaired {short}.");
            println!("That device must scan a fresh QR before it can connect again.");
            Ok(())
        }
        Ok(false) => bail!("{short} was already gone."),
        Err(error) => Err(anyhow!(
            "Nothing was revoked: the Ciao daemon is not reachable ({error}). \
             Start it with `ciao setup --yes`, then retry."
        )),
    }
}

/// Whole days, because what this answers is "is that one stale", not "when exactly".
fn describe_age(seconds: u64) -> String {
    match seconds / 86_400 {
        0 => "today".into(),
        1 => "yesterday".into(),
        days => format!("{days} days ago"),
    }
}

async fn status_command(paths: &CiaoPaths, json_output: bool, strict: bool) -> Result<()> {
    let identity = load_identity(paths)?;
    let Some(identity) = identity else {
        if json_output {
            let value = serde_json::json!({
                "v": 1,
                "daemon": "unconfigured",
                "iroh": "unknown",
                "host_endpoint_id": null,
                "host_endpoint_id_short": null,
                "paired_devices": 0,
                "active_connections": null,
                "version": env!("CARGO_PKG_VERSION"),
                "protocol": crate::host_protocol::HOST_PROTOCOL_VERSION,
                "platform": crate::host_info::platform_token(),
                "active_terminals": null,
                "active_agent_sessions": null,
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            println!("Ciao is not set up.\n\nRun `ciao setup --yes` to configure it.");
        }
        return if strict {
            Err(anyhow!("Ciao is not configured"))
        } else {
            Ok(())
        };
    };

    let daemon_status = request_status(&paths.socket_file).await;
    let (status, reachable) = match daemon_status {
        Ok(status) => (status, true),
        Err(_) => {
            let paired = PairedDeviceStore::load(&paths.paired_devices_file)?.len();
            (
                DaemonStatus {
                    v: 1,
                    daemon: "unreachable".into(),
                    iroh: "unknown".into(),
                    host_endpoint_id: identity.endpoint_id.to_string(),
                    host_endpoint_id_short: daemon::short_endpoint_id(identity.endpoint_id),
                    paired_devices: paired,
                    active_connections: None,
                    version: Some(env!("CARGO_PKG_VERSION").into()),
                    protocol: Some(crate::host_protocol::HOST_PROTOCOL_VERSION),
                    platform: Some(crate::host_info::platform_token().into()),
                    active_terminals: None,
                    active_agent_sessions: None,
                    active_managed_workers: None,
                    resumable_terminals: None,
                    active_terminal_devices: None,
                },
                false,
            )
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Ciao is configured.");
        println!("Daemon: {}", status.daemon);
        println!(
            "Version: {}",
            status.version.as_deref().unwrap_or("unknown")
        );
        println!(
            "Platform: {}",
            status.platform.as_deref().unwrap_or("unknown")
        );
        match status.protocol {
            Some(protocol) => println!("Protocol: {protocol}"),
            None => println!("Protocol: unknown"),
        }
        println!("Iroh: {}", status.iroh);
        // Which rung is keeping the daemon alive was previously unanswerable without
        // inspecting the systemd unit and the crontab by hand.
        println!("Supervisor: {}", describe_supervisor());
        println!("Host: {}", status.host_endpoint_id_short);
        println!("Paired devices: {}", status.paired_devices);
        match status.active_connections {
            Some(count) => println!("Active connections: {count}"),
            None => println!("Active connections: unknown"),
        }
        match status.active_terminals {
            // Naming the devices is the whole point of the line when the count disagrees with
            // what the operator believes they closed.
            Some(count) => println!("Active terminals: {count}{}", terminal_devices(&status)),
            None => println!("Active terminals: unknown"),
        }
        match status.active_agent_sessions {
            Some(count) => println!("Active agent sessions: {count}"),
            None => println!("Active agent sessions: unknown"),
        }
        // This trailing line is the only guidance most operators read, so it has to match the
        // state above it. Sending someone to `ciao pair` while nothing is answering just
        // produces a second, worse error, and "another device" is wrong when none are paired.
        if !reachable {
            println!(
                "\nThe daemon is not running. Start it, then pair from another shell:\n\n    ciao daemon\n    ciao pair"
            );
        } else if status.paired_devices == 0 {
            println!("\nRun `ciao pair` to pair your iPhone.");
        } else {
            println!("\nRun `ciao pair` to pair another device.");
        }
    }

    if strict && !reachable {
        bail!(
            "Ciao daemon is unreachable. Start it with `ciao daemon`, or rerun \
             `ciao setup --yes` to install a supervised service; logs: {}",
            paths.log_hint()
        );
    }
    Ok(())
}

/// Requires the daemon that answers to be the one setup just installed — the right identity
/// *and* the version of the binary being installed.
///
/// Checking the endpoint alone let a whole family of failures report success: a stale daemon
/// serving an older binary answers with the same identity, because identity belongs to the host
/// and not to the build. That is precisely how the `@reboot` rung silently kept an old daemon
/// after a reinstall — the spawn refused, the old process answered, and setup called it done.
/// The cause is fixed on that rung; this is the check that should have caught it regardless.
async fn wait_for_daemon(
    paths: &CiaoPaths,
    expected_endpoint_id: String,
    expected_version: &str,
) -> Result<()> {
    let deadline = Instant::now() + DAEMON_START_TIMEOUT;
    let mut answered_version: Option<String> = None;
    loop {
        if let Ok(status) = request_status(&paths.socket_file).await
            && status.host_endpoint_id == expected_endpoint_id
        {
            if status.version.as_deref() == Some(expected_version) {
                return Ok(());
            }
            // Keep the last mismatch so the failure can name what is actually running rather
            // than only what was wanted.
            answered_version = status.version.clone();
        }
        if Instant::now() >= deadline {
            if let Some(running) = answered_version {
                bail!(
                    "the daemon answering is still version {running}, not the {expected_version} just installed. The old daemon did not stop; stop it and rerun `ciao setup --yes`. Inspect {}.",
                    paths.log_hint()
                );
            }
            bail!(
                "daemon did not answer within {} seconds. Identity and service files were preserved. Inspect {} and rerun `ciao setup --yes`.",
                DAEMON_START_TIMEOUT.as_secs(),
                paths.log_hint()
            );
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_online(paths: &CiaoPaths) -> Result<()> {
    let deadline = Instant::now() + RELAY_ONLINE_TIMEOUT;
    loop {
        let status = request_status(&paths.socket_file)
            .await
            .context("daemon became unreachable while waiting for Iroh")?;
        if status.iroh == "online" {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "Iroh relay did not become online within {} seconds (last state: {}). Identity and service remain installed. Inspect {}.",
                RELAY_ONLINE_TIMEOUT.as_secs(),
                status.iroh,
                paths.log_hint()
            );
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_shape_contains_only_accepted_commands() {
        use clap::CommandFactory as _;
        let command = Cli::command();
        let names: Vec<_> = command
            .get_subcommands()
            .map(|subcommand| subcommand.get_name())
            .collect();
        assert_eq!(
            names,
            [
                "setup",
                "pair",
                "status",
                "unpair",
                "install",
                "update",
                "agent",
                "drift",
                "reset",
                "daemon",
                "__claude-hook",
                "__codex-hook",
            ]
        );
        for hidden in ["__claude-hook", "__codex-hook"] {
            assert!(
                command
                    .get_subcommands()
                    .find(|subcommand| subcommand.get_name() == hidden)
                    .is_some_and(clap::Command::is_hide_set)
            );
        }
    }

    /// Both spellings the operator is likely to type reach the same command, and the channel
    /// stays overridable without becoming mandatory.
    #[test]
    fn update_accepts_its_alias_and_an_optional_channel() {
        assert!(Cli::try_parse_from(["ciao", "update"]).is_ok());
        assert!(Cli::try_parse_from(["ciao", "upgrade"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "ciao",
                "update",
                "--release-base",
                "https://example.test/dist"
            ])
            .is_ok()
        );
        // Update reads the version from the channel; declaring one is the strict path's job.
        assert!(Cli::try_parse_from(["ciao", "update", "--version", "0.1.9"]).is_err());
    }

    /// What the installer promises to put back. Missing a live managed chat leaves it stopped
    /// after an update that said it would resume it; picking up an attached one would try to
    /// start a conversation running in someone's own terminal, which Ciao does not own.
    #[test]
    fn only_ciaos_own_live_workers_are_restored_after_a_restart() {
        let row = |session_id: &str, topology: &str, presence: &str| ipc::ManagedSessionRow {
            session_id: session_id.into(),
            presence: presence.into(),
            stored_reason: None,
            workspace_label: "ciao".into(),
            process_generation: 1,
            updated_at: 0,
            topology: topology.into(),
        };
        let ids = live_managed_ids(vec![
            row("live-managed", "managed", "live"),
            row("stored-managed", "managed", "stored"),
            row("live-attached", "attached", "live"),
            row("second-live", "managed", "live"),
        ]);
        assert_eq!(ids, vec!["live-managed", "second-live"]);
        assert!(live_managed_ids(Vec::new()).is_empty());
    }

    #[test]
    fn update_resolves_this_target_and_stops_when_already_current() {
        let manifest = crate::install::parse_manifest(
            br#"{"v":1,"artifacts":[
                {"version":"0.2.0","target":"aarch64-apple-darwin",
                 "file":"ciao-0.2.0-aarch64-apple-darwin.tar",
                 "sha256":"28a0ce01a05b4714fcc93aed8b06517709ddc64681740c5c45cba47e80842eec",
                 "bytes":1024},
                {"version":"0.2.0","target":"x86_64-unknown-linux-gnu",
                 "file":"ciao-0.2.0-x86_64-unknown-linux-gnu.tar",
                 "sha256":"a6696baa1de5460b4e74b69ae430be332abe7c5fa6b3f4ce51df7c86582eb238",
                 "bytes":2048}]}"#,
        )
        .unwrap();

        // Picks the entry for this host, not merely the first entry in the file.
        let linux = update_artifact(&manifest, "x86_64-unknown-linux-gnu", "0.1.9")
            .unwrap()
            .expect("a newer release is an update");
        assert_eq!(linux.target, "x86_64-unknown-linux-gnu");
        assert_eq!(linux.version, "0.2.0");

        // Already there: no download, no service restart, no rollback slot consumed.
        assert!(
            update_artifact(&manifest, "aarch64-apple-darwin", "0.2.0")
                .unwrap()
                .is_none()
        );

        // A channel that does not build for this host says so instead of installing something else.
        assert!(update_artifact(&manifest, "riscv64-unknown-linux-gnu", "0.1.9").is_err());
    }

    #[test]
    fn agent_integration_commands_require_an_explicit_registered_provider() {
        use clap::CommandFactory as _;

        assert!(Cli::try_parse_from(["ciao", "agent", "install", "pi"]).is_ok());
        assert!(Cli::try_parse_from(["ciao", "agent", "status", "pi"]).is_ok());
        assert!(Cli::try_parse_from(["ciao", "agent", "install", "claude"]).is_ok());
        assert!(Cli::try_parse_from(["ciao", "agent", "status", "claude"]).is_ok());
        assert!(Cli::try_parse_from(["ciao", "agent", "install", "claude-managed"]).is_ok());
        assert!(Cli::try_parse_from(["ciao", "agent", "install", "codex"]).is_ok());
        assert!(Cli::try_parse_from(["ciao", "agent", "status", "codex"]).is_ok());
        assert!(Cli::try_parse_from(["ciao", "agent", "install"]).is_err());
        assert!(Cli::try_parse_from(["ciao", "agent", "install", "unknown"]).is_err());

        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("agent")
            .unwrap()
            .find_subcommand_mut("install")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("- claude:"));
        assert!(!help.contains("claude-managed"));
    }

    #[test]
    fn setup_prompt_accepts_default_yes_and_no_and_retries_other_input() {
        assert_eq!(parse_setup_answer("\n"), Some(true));
        assert_eq!(parse_setup_answer("y\n"), Some(true));
        assert_eq!(parse_setup_answer("Y\n"), Some(true));
        assert_eq!(parse_setup_answer("n\n"), Some(false));
        assert_eq!(parse_setup_answer("N\n"), Some(false));
        assert_eq!(parse_setup_answer("later\n"), None);
    }

    #[test]
    fn agent_selection_accepts_the_detected_default_edited_lists_and_none() {
        let detected = vec![AgentIntegration::Claude, AgentIntegration::Pi];
        // Enter (and reflexive yes-spellings) take the pre-selected detected set.
        assert_eq!(
            parse_agent_selection("\n", &detected),
            Some(detected.clone())
        );
        assert_eq!(
            parse_agent_selection("y\n", &detected),
            Some(detected.clone())
        );
        // Opting out entirely stays one short word.
        assert_eq!(parse_agent_selection("none\n", &detected), Some(Vec::new()));
        assert_eq!(parse_agent_selection("n\n", &detected), Some(Vec::new()));
        // A typed list replaces the pre-selection: spaces or commas, any case, duplicates
        // collapsed, and an undetected agent may still be chosen by name.
        assert_eq!(
            parse_agent_selection("codex, Claude claude\n", &detected),
            Some(vec![AgentIntegration::Codex, AgentIntegration::Claude])
        );
        // An unrecognized token rejects the whole answer so the prompt asks again, rather
        // than installing a subset of what the person meant.
        assert_eq!(parse_agent_selection("claude emacs\n", &detected), None);
    }

    #[test]
    fn pairing_status_json_decodes_without_qr_or_capability() {
        let value: serde_json::Value = serde_json::json!({
            "state": "connected",
            "installation_endpoint_id": "ab".repeat(32),
            "connected": true
        });
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(!encoded.contains("capability"));
        assert!(!encoded.contains("qr_uri"));
        let status: PairingStatus = serde_json::from_value(value).unwrap();
        assert!(status.connected);
    }
}
