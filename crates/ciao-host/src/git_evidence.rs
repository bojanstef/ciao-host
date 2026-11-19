//! An on-demand observation of a session checkout. Only a second, explicit request can
//! consult GitHub Actions, and its target must still match the one the phone just displayed.

use std::{path::Path, process::Stdio, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

use crate::{
    git_diff::{GitDiffError, open_work_tree, run_git},
    pty::{apply_clean_process_environment, is_absolute_executable},
};

const MAX_RUNS: usize = 6;
const MAX_API_BYTES: u64 = 512 * 1024;
const API_DEADLINE: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceTarget {
    repository: String,
    revision: String,
    branch: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Evidence {
    v: u8,
    session: String,
    workspace: String,
    branch: Option<String>,
    revision: Option<String>,
    worktree: Worktree,
    repository: Option<String>,
    checks: Checks,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Worktree {
    Clean,
    Modified,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LookupState {
    #[default]
    NotRequested,
    Loaded,
    Unavailable,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
struct Checks {
    state: LookupState,
    total: u64,
    runs: Vec<Run>,
    other_revision: Option<Run>,
    other_lookup_unavailable: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Run {
    id: u64,
    attempt: u32,
    name: String,
    revision: String,
    status: RunStatus,
    conclusion: Option<Conclusion>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RunStatus {
    Requested,
    Waiting,
    Pending,
    Queued,
    InProgress,
    Completed,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Conclusion {
    Success,
    Failure,
    Neutral,
    Cancelled,
    Skipped,
    TimedOut,
    ActionRequired,
    Stale,
    StartupFailure,
    #[serde(other)]
    Unknown,
}

fn valid_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Recognize only standard github.com clone URLs. Never forward raw configuration: a URL
/// may include credentials, custom hosts, query parameters or an unrelated path.
fn github_repository(remote: &[u8]) -> Option<String> {
    let remote = std::str::from_utf8(remote).ok()?.strip_suffix('\n')?;
    let path = [
        "https://github.com/",
        "git@github.com:",
        "ssh://git@github.com/",
    ]
    .iter()
    .find_map(|prefix| remote.strip_prefix(prefix))?;
    let path = path.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let (owner, repo) = path.split_once('/')?;
    if owner.is_empty()
        || owner.len() > 39
        || repo.is_empty()
        || repo.len() > 100
        || matches!(repo, "." | "..")
        || !owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || !repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return None;
    }
    Some(path.to_owned())
}

fn safe_char(ch: char) -> bool {
    !ch.is_control()
        && !matches!(ch, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn display_label(value: &str, fallback: &str) -> String {
    let mut label = String::new();
    for ch in value.chars() {
        if !safe_char(ch) {
            continue;
        }
        if label.len() + ch.len_utf8() > 128 {
            break;
        }
        label.push(ch);
    }
    if label.trim().is_empty() {
        fallback.to_owned()
    } else {
        label
    }
}

/// Git's porcelain v2 branch headers bind HEAD and dirty records to the same status read.
/// Paths can contain arbitrary bytes; their contents are never decoded for display.
fn checkout_status(
    bytes: &[u8],
) -> Result<(Option<String>, Option<String>, Worktree), GitDiffError> {
    let mut records = bytes.split(|b| *b == 0);
    let oid = records
        .next()
        .and_then(|line| line.strip_prefix(b"# branch.oid "))
        .ok_or(GitDiffError::Failed)?;
    let revision = match oid {
        b"(initial)" => None,
        value => Some(
            std::str::from_utf8(value)
                .ok()
                .filter(|oid| valid_revision(oid))
                .ok_or(GitDiffError::Failed)?
                .to_owned(),
        ),
    };
    let name = records
        .next()
        .and_then(|line| line.strip_prefix(b"# branch.head "))
        .ok_or(GitDiffError::Failed)?;
    let branch = std::str::from_utf8(name)
        .ok()
        .filter(|name| {
            *name != "(detached)"
                && !name.is_empty()
                && name.len() <= 255
                && name.chars().all(safe_char)
        })
        .map(str::to_owned);
    let modified = records.any(|line| !line.is_empty() && !line.starts_with(b"# "));
    Ok((
        revision,
        branch,
        if modified {
            Worktree::Modified
        } else {
            Worktree::Clean
        },
    ))
}

impl Evidence {
    pub(crate) async fn read(
        session: &str,
        workdir: &Path,
        target: Option<&EvidenceTarget>,
    ) -> Result<Self, GitDiffError> {
        let (git, root) = open_work_tree(workdir).await?;
        let status = run_git(
            &git,
            &root,
            &[
                "status",
                "--porcelain=v2",
                "--branch",
                "--no-ahead-behind",
                "--untracked-files=normal",
                "--ignore-submodules=none",
                "-z",
            ],
        )
        .await?;
        if status.truncated || status.had_diagnostics || status.exit_code != Some(0) {
            return Err(GitDiffError::Failed);
        }
        let (revision, branch, worktree) = checkout_status(&status.stdout)?;
        let remote = run_git(&git, &root, &["remote", "get-url", "origin"]).await?;
        let repository =
            (remote.exit_code == Some(0) && !remote.truncated && !remote.had_diagnostics)
                .then(|| github_repository(&remote.stdout))
                .flatten();
        let mut result = Self {
            v: 1,
            session: session.to_owned(),
            workspace: display_label(
                root.file_name().and_then(|v| v.to_str()).unwrap_or(""),
                "Workspace",
            ),
            branch,
            revision,
            worktree,
            repository,
            checks: Checks::default(),
        };
        if let (Some(expected), Some(repository), Some(revision)) =
            (target, &result.repository, &result.revision)
        {
            let local = EvidenceTarget {
                repository: repository.clone(),
                revision: revision.clone(),
                branch: result.branch.clone(),
            };
            if *expected == local {
                result.checks = lookup_actions(&local, &GitHub).await;
            }
        }
        Ok(result)
    }
}

#[derive(Deserialize)]
struct WorkflowPage {
    total_count: u64,
    workflow_runs: Vec<WorkflowRun>,
}

#[derive(Deserialize)]
struct RunRepository {
    full_name: String,
}

#[derive(Deserialize)]
struct WorkflowRun {
    id: u64,
    run_attempt: u32,
    name: String,
    head_sha: String,
    head_branch: Option<String>,
    status: RunStatus,
    conclusion: Option<Conclusion>,
    repository: RunRepository,
    head_repository: Option<RunRepository>,
}

impl WorkflowRun {
    fn into_run(self, repository: &str) -> Result<Run, ()> {
        if self.id == 0
            || self.run_attempt == 0
            || !valid_revision(&self.head_sha)
            || !self.repository.full_name.eq_ignore_ascii_case(repository)
            || !self
                .head_repository
                .is_some_and(|repo| repo.full_name.eq_ignore_ascii_case(repository))
        {
            return Err(());
        }
        Ok(Run {
            id: self.id,
            attempt: self.run_attempt,
            name: display_label(&self.name, "Workflow"),
            revision: self.head_sha,
            status: self.status,
            conclusion: self.conclusion,
        })
    }
}

trait WorkflowSource {
    async fn page(&self, endpoint: &str) -> Result<WorkflowPage, ()>;
}

struct GitHub;

impl WorkflowSource for GitHub {
    async fn page(&self, endpoint: &str) -> Result<WorkflowPage, ()> {
        let cli = ["/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh"]
            .into_iter()
            .map(Path::new)
            .find(|path| is_absolute_executable(path));
        if let Some(gh) = cli {
            let (status, bytes) = api_output(
                gh,
                &[
                    "api",
                    "--hostname",
                    "github.com",
                    "--method",
                    "GET",
                    endpoint,
                ],
            )
            .await?;
            match status {
                Some(0) => return serde_json::from_slice(&bytes).map_err(|_| ()),
                Some(4) => {} // No logged-in host CLI; public repositories can use anonymous HTTPS.
                _ => return Err(()),
            }
        }
        let url = format!("https://api.github.com/{endpoint}");
        let (status, bytes) = api_output(
            Path::new("/usr/bin/curl"),
            &[
                "--disable",
                "--silent",
                "--fail",
                "--proto",
                "=https",
                "--header",
                "Accept: application/vnd.github+json",
                &url,
            ],
        )
        .await?;
        if status != Some(0) {
            return Err(());
        }
        serde_json::from_slice(&bytes).map_err(|_| ())
    }
}

async fn api_output(program: &Path, args: &[&str]) -> Result<(Option<i32>, Vec<u8>), ()> {
    let mut command = Command::new(program);
    apply_clean_process_environment(&mut command).map_err(|_| ())?;
    command
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_NO_UPDATE_NOTIFIER", "1")
        .env("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1");
    let mut child = command.spawn().map_err(|_| ())?;
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .ok_or(())?
        .take(MAX_API_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_API_BYTES {
        return Err(());
    }
    let status = child.wait().await.map_err(|_| ())?.code();
    Ok((status, bytes))
}

fn encode_query(value: &str) -> String {
    use std::fmt::Write;
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"._~-".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            write!(encoded, "%{byte:02X}").expect("writing to a String");
        }
    }
    encoded
}

async fn lookup_actions(target: &EvidenceTarget, source: &impl WorkflowSource) -> Checks {
    let endpoint = format!("repos/{}/actions/runs", target.repository);
    let exact = format!(
        "{endpoint}?head_sha={}&per_page={MAX_RUNS}",
        target.revision
    );
    let unavailable = || Checks {
        state: LookupState::Unavailable,
        ..Checks::default()
    };
    let exact_checks = || async {
        let page = timeout(API_DEADLINE, source.page(&exact))
            .await
            .map_err(|_| ())??;
        let (total, runs) = validate_exact(page, target)?;
        Ok::<_, ()>(Checks {
            state: LookupState::Loaded,
            total,
            runs,
            ..Checks::default()
        })
    };
    let Ok(mut checks) = exact_checks().await else {
        return unavailable();
    };
    if checks.total == 0
        && let Some(branch) = &target.branch
    {
        let previous = format!("{endpoint}?branch={}&per_page=1", encode_query(branch));
        let other = timeout(API_DEADLINE, source.page(&previous))
            .await
            .map_err(|_| ())
            .flatten()
            .and_then(|page| validate_other(page, target));
        match other {
            // An exact run appeared after the initial lookup. Refresh the exact list once:
            // the branch page alone cannot tell us how many workflows ran for this commit.
            Ok(Some(run)) if run.revision == target.revision => {
                return exact_checks()
                    .await
                    .ok()
                    .filter(|current| current.total > 0)
                    .unwrap_or_else(unavailable);
            }
            Ok(run) => checks.other_revision = run,
            Err(()) => checks.other_lookup_unavailable = true,
        }
    }
    checks
}

fn validate_exact(page: WorkflowPage, target: &EvidenceTarget) -> Result<(u64, Vec<Run>), ()> {
    let expected = page.total_count.min(MAX_RUNS as u64);
    if page.workflow_runs.len() as u64 != expected {
        return Err(());
    }
    let mut runs = Vec::new();
    for item in page.workflow_runs {
        if item.head_sha != target.revision || runs.iter().any(|run: &Run| run.id == item.id) {
            return Err(());
        }
        runs.push(item.into_run(&target.repository)?);
    }
    Ok((page.total_count, runs))
}

fn validate_other(mut page: WorkflowPage, target: &EvidenceTarget) -> Result<Option<Run>, ()> {
    if page.workflow_runs.len() as u64 != page.total_count.min(1) {
        return Err(());
    }
    let Some(item) = page.workflow_runs.pop() else {
        return Ok(None);
    };
    if item.head_branch != target.branch {
        return Err(());
    }
    item.into_run(&target.repository).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::{collections::VecDeque, path::PathBuf, sync::Mutex};

    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../../protocol/fixtures/phase9/git-evidence-v1.json"
        ))
        .unwrap()
    }

    fn target() -> EvidenceTarget {
        serde_json::from_value(fixture()["github_request"]["evidence_target"].clone()).unwrap()
    }

    fn page(rows: Vec<Value>) -> Value {
        json!({ "total_count": rows.len(), "workflow_runs": rows })
    }

    fn row(revision: &str) -> Value {
        let target = target();
        json!({"id":12345,"run_attempt":2,"name":"Unit tests","head_sha":revision,"head_branch":"main",
               "repository":{"full_name":target.repository},"head_repository":{"full_name":target.repository},
               "status":"completed","conclusion":"success"})
    }

    #[derive(Default)]
    struct Responses {
        pages: Mutex<VecDeque<Value>>,
        requests: Mutex<Vec<String>>,
    }

    impl Responses {
        fn given(pages: impl IntoIterator<Item = Value>) -> Self {
            Self {
                pages: Mutex::new(pages.into_iter().collect()),
                ..Self::default()
            }
        }
    }

    impl WorkflowSource for Responses {
        async fn page(&self, endpoint: &str) -> Result<WorkflowPage, ()> {
            self.requests.lock().unwrap().push(endpoint.to_owned());
            serde_json::from_value(self.pages.lock().unwrap().pop_front().ok_or(())?)
                .map_err(|_| ())
        }
    }

    #[tokio::test]
    async fn exact_results_bind_the_workflow_repository_and_full_commit() {
        let target = target();
        let source = Responses::given([page(vec![row(&target.revision)])]);
        let result = lookup_actions(&target, &source).await;
        assert_eq!(
            serde_json::to_value(&result).unwrap(),
            fixture()["exact"]["checks"]
        );
        assert_eq!(
            source.requests.lock().unwrap().as_slice(),
            [format!(
                "repos/example/field-notes/actions/runs?head_sha={}&per_page=6",
                target.revision
            )]
        );
        for field in ["head_sha", "repository", "head_repository"] {
            let mut wrong = row(&target.revision);
            wrong[field] = if field == "head_sha" {
                json!("b".repeat(40))
            } else {
                json!({"full_name":"elsewhere/field-notes"})
            };
            let result = lookup_actions(&target, &Responses::given([page(vec![wrong])])).await;
            assert_eq!(
                serde_json::to_value(result).unwrap(),
                fixture()["unavailable"]["checks"],
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn a_recent_other_commit_cannot_count_as_success_for_head() {
        let target = target();
        let mut older = row(&"b".repeat(40));
        older["id"] = json!(12344);
        let source = Responses::given([page(vec![]), page(vec![older.clone()])]);
        let checks = lookup_actions(&target, &source).await;
        assert_eq!(
            serde_json::to_value(checks).unwrap(),
            fixture()["other"]["checks"]
        );
        assert_eq!(
            source.requests.lock().unwrap().last().unwrap(),
            "repos/example/field-notes/actions/runs?branch=main&per_page=1"
        );
        older["head_branch"] = json!("unrelated");
        let result = lookup_actions(
            &target,
            &Responses::given([page(vec![]), page(vec![older])]),
        )
        .await;
        assert!(result.other_revision.is_none() && result.other_lookup_unavailable);
        assert_eq!(result.state, LookupState::Loaded);
        let raced = lookup_actions(
            &target,
            &Responses::given([page(vec![]), page(vec![row(&target.revision)])]),
        )
        .await;
        assert_eq!(raced.state, LookupState::Unavailable);
        let exact = page(vec![row(&target.revision)]);
        let again = Responses::given([page(vec![]), exact.clone(), exact]);
        let raced = lookup_actions(&target, &again).await;
        assert_eq!(
            serde_json::to_value(raced).unwrap(),
            fixture()["exact"]["checks"]
        );
        assert_eq!(again.requests.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn missing_results_and_inaccessible_results_stay_distinct() {
        let mut target = target();
        let inaccessible = lookup_actions(&target, &Responses::default()).await;
        assert_eq!(inaccessible.state, LookupState::Unavailable);
        let unavailable_prior = lookup_actions(&target, &Responses::given([page(vec![])])).await;
        assert_eq!(unavailable_prior.state, LookupState::Loaded);
        assert!(unavailable_prior.other_lookup_unavailable);
        target.branch = None;
        let empty = Responses::given([page(vec![])]);
        let result = lookup_actions(&target, &empty).await;
        assert_eq!(result.state, LookupState::Loaded);
        assert!(!result.other_lookup_unavailable);
        assert_eq!(empty.requests.lock().unwrap().len(), 1);
        assert_eq!(encode_query("feat/a&b=1"), "feat%2Fa%26b%3D1");
    }

    #[tokio::test]
    async fn sampled_checkout_refuses_drift_without_contacting_github() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("field-notes");
        std::fs::create_dir(&dir).unwrap();
        let git = crate::git_diff::resolve_git().unwrap();
        let command = |args: &[&str]| {
            let output = std::process::Command::new(&git)
                .arg("-C")
                .arg(&dir)
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "{args:?}");
            output.stdout
        };
        command(&["init", "-q", "-b", "main"]);
        command(&[
            "remote",
            "add",
            "origin",
            "git@github.com:example/field-notes.git",
        ]);
        let target = target();
        std::fs::write(dir.join("draft.txt"), "hello").unwrap();
        let unborn = Evidence::read("session-1", &dir, Some(&target))
            .await
            .unwrap();
        assert_eq!(serde_json::to_value(unborn).unwrap(), fixture()["unborn"]);
        command(&["add", "draft.txt"]);
        command(&[
            "-c",
            "user.name=Example",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "seed",
        ]);
        let oid = String::from_utf8(command(&["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned();
        let child = dir.join("nested");
        std::fs::create_dir(&child).unwrap();
        let observation = Evidence::read("session-1", &child, Some(&target))
            .await
            .unwrap();
        let mut wanted = fixture()["local"].clone();
        wanted["revision"] = json!(oid);
        assert_eq!(serde_json::to_value(observation).unwrap(), wanted);
        std::fs::write(dir.join("draft.txt"), "changed").unwrap();
        command(&["add", "draft.txt"]);
        command(&["checkout", "-q", "--detach"]);
        let observation = Evidence::read("session-1", &child, None).await.unwrap();
        assert_eq!(observation.revision.as_deref(), Some(oid.as_str()));
        assert_eq!(observation.worktree, Worktree::Modified);
        assert!(observation.branch.is_none());
        command(&[
            "remote",
            "set-url",
            "origin",
            "https://example.invalid/team/project.git",
        ]);
        assert!(
            Evidence::read("session-1", &dir, None)
                .await
                .unwrap()
                .repository
                .is_none()
        );
    }

    #[tokio::test]
    async fn unreadable_untracked_subtree_cannot_be_reported_clean() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::Uid::effective().is_root() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        assert!(
            std::process::Command::new(crate::git_diff::resolve_git().unwrap())
                .arg("-C")
                .arg(root)
                .args(["init", "-q"])
                .status()
                .unwrap()
                .success()
        );
        let hidden = root.join("hidden");
        std::fs::create_dir(&hidden).unwrap();
        std::fs::write(hidden.join("item"), b"new").unwrap();
        std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = Evidence::read("session-1", root, None).await;
        std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result, Err(GitDiffError::Failed));
        assert_eq!(
            Evidence::read("session-1", root, None)
                .await
                .unwrap()
                .worktree,
            Worktree::Modified
        );
    }

    #[test]
    fn raw_remote_configuration_stays_on_the_host() {
        for url in [
            "git@github.com:owner/project.git",
            "ssh://git@github.com/owner/project.git",
            "https://github.com/owner/project.git/",
        ] {
            assert_eq!(
                github_repository(format!("{url}\n").as_bytes()).as_deref(),
                Some("owner/project")
            );
        }
        for url in [
            "https://token@github.com/owner/project",
            "https://github.com/owner/project?access=secret",
            "https://example.invalid/owner/project",
            "https://github.com/../repo",
            "https://github.com/a/..",
            "https://github.com/a/b/c",
            "https://github.com/a/%2f",
            "/local/path",
        ] {
            assert!(
                github_repository(format!("{url}\n").as_bytes()).is_none(),
                "{url}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "reads the GitHub Actions API for a real, operator-selected checkout"]
    async fn explicit_live_checkout_actions_lookup() {
        let dir =
            PathBuf::from(std::env::var_os("CIAO_LIVE_EVIDENCE_CHECKOUT").expect("checkout path"));
        let local = Evidence::read("live-test", &dir, None).await.unwrap();
        let target = EvidenceTarget {
            repository: local.repository.unwrap(),
            revision: local.revision.unwrap(),
            branch: local.branch,
        };
        let evidence = Evidence::read("live-test", &dir, Some(&target))
            .await
            .unwrap();
        assert_eq!(evidence.checks.state, LookupState::Loaded);
        if std::env::var_os("CIAO_LIVE_EVIDENCE_OTHER_REVISION").is_some() {
            assert_eq!(evidence.checks.total, 0);
            assert_ne!(
                evidence.checks.other_revision.as_ref().unwrap().revision,
                target.revision
            );
        } else {
            assert!(evidence.checks.total > 0 && !evidence.checks.runs.is_empty());
        }
        println!(
            "Exact GitHub Actions results: {} of {}. Worktree: {:?}.",
            evidence.checks.runs.len(),
            evidence.checks.total,
            evidence.worktree
        );
    }
}
