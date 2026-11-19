//! Spec 008 spike — the uncommitted diff of one workspace, as one patch string.
//!
//! Deliberately not Spec 008 §5.3's snapshot. There is no manifest, no per-file record, no
//! opaque file IDs, or snapshot lifetime. An uncommitted review includes bounded coverage of
//! untracked files alongside the bytes
//! `git diff` produces so the renderer can be judged against a real repository. The structured
//! snapshot is the thing to build once the renderer decision is settled.
//!
//! What is *not* provisional is the process policy, because loosening it later is harder than
//! writing it now: a fixed absolute binary, fixed argv, no shell, the PTY broker's cleaned
//! environment, a deadline, and a hard output cap. Repository config is never modified, and
//! stderr never leaves this module — a refusal must not become a filesystem probe.

use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

use crate::pty::{apply_clean_process_environment, is_absolute_executable};

/// Where git may be found. Joined with the name and nothing else — there is no `PATH` search,
/// for the same reason `workspace.rs` refuses one for multiplexers.
const GIT_BINARY_DIRS: &[&str] = &["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/bin"];

/// Spec 008 §5.3 puts 1 MiB on a single file's patch. The spike has no per-file structure to
/// bound, so the same number bounds the whole thing: past this the phone is not the right place
/// to be reading the change anyway.
const MAX_DIFF_BYTES: usize = 1024 * 1024;

/// Long enough for a cold index on a large repository, short enough that a wedged git does not
/// hold the download stream open to its own idle timeout.
const GIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Untracked files rendered as additions before the rest are counted and named instead. An
/// agent that just scaffolded a project can produce hundreds, and each costs its own git call.
const MAX_UNTRACKED_FILES: usize = 50;

/// Git's empty tree. Diffing against this is how an unborn repository — one where `HEAD` does
/// not resolve because nothing is committed yet — still shows its work.
const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitDiffError {
    /// No git binary in the fixed directories.
    GitUnavailable,
    /// The directory exists but is not inside a work tree, or is a bare repository.
    NotARepository,
    /// git ran and failed. The reason stays here.
    Failed,
    /// The diff exceeded `MAX_DIFF_BYTES`.
    TooLarge,
    Timeout,
}

pub(crate) fn resolve_git() -> Option<PathBuf> {
    GIT_BINARY_DIRS
        .iter()
        .map(|dir| Path::new(dir).join("git"))
        .find(|candidate| is_absolute_executable(candidate))
}

pub(super) struct GitOutput {
    pub(super) exit_code: Option<i32>,
    pub(super) stdout: Vec<u8>,
    pub(super) truncated: bool,
    pub(super) had_diagnostics: bool,
}

impl GitOutput {
    pub(super) fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Capture bounded stdout and only the presence of diagnostics. Git can report unreadable
/// directories on stderr but exit successfully when enumerating untracked files.
pub(super) async fn run_git(
    git: &Path,
    workdir: &Path,
    args: &[&str],
) -> Result<GitOutput, GitDiffError> {
    let mut command = Command::new(git);
    command
        .arg("-C")
        .arg(workdir)
        .args([
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.pager=cat",
            "-c",
            "diff.external=",
            "-c",
            "core.fsmonitor=false",
        ])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    apply_clean_process_environment(&mut command).map_err(|_| GitDiffError::Failed)?;

    let mut child = command.spawn().map_err(|_| GitDiffError::GitUnavailable)?;
    let stdout = child.stdout.take().ok_or(GitDiffError::Failed)?;
    let mut stderr = child.stderr.take().ok_or(GitDiffError::Failed)?;

    let collected = timeout(GIT_TIMEOUT, async {
        let mut buffer = Vec::new();
        let read_stdout = async {
            stdout
                .take(MAX_DIFF_BYTES as u64 + 1)
                .read_to_end(&mut buffer)
                .await
                .map_err(|_| GitDiffError::Failed)?;
            if buffer.len() > MAX_DIFF_BYTES {
                return Err(GitDiffError::TooLarge);
            }
            Ok(())
        };
        let drain_stderr = async {
            tokio::io::copy(&mut stderr, &mut tokio::io::sink())
                .await
                .map_err(|_| GitDiffError::Failed)
        };
        // Returning at the cap drops and kills the child. Waiting with a full stdout pipe
        // would block its writer until the entire command deadline expired.
        let (_, diagnostics, status) = tokio::try_join!(read_stdout, drain_stderr, async {
            child.wait().await.map_err(|_| GitDiffError::Failed)
        })?;
        Ok(GitOutput {
            exit_code: status.code(),
            stdout: buffer,
            truncated: false,
            had_diagnostics: diagnostics > 0,
        })
    })
    .await
    .map_err(|_| GitDiffError::Timeout)?;
    match collected {
        Err(GitDiffError::TooLarge) => Ok(GitOutput {
            exit_code: None,
            stdout: Vec::new(),
            truncated: true,
            had_diagnostics: false,
        }),
        other => other,
    }
}

/// Which range of history the reader is looking at.
///
/// A closed token set, and that is the security property: the phone picks from the list this
/// module enumerated, so no string the phone chose ever reaches git's argv. A revision on the
/// wire would put the caller in charge of what "base" means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiffBase {
    /// Everything not yet committed — staged, unstaged, and untracked.
    Uncommitted,
    /// Every commit this branch has that its base branch does not: what a merge would bring.
    Branch,
}

impl DiffBase {
    pub(crate) const fn wire(self) -> &'static str {
        match self {
            Self::Uncommitted => "uncommitted",
            Self::Branch => "branch",
        }
    }

    /// `None` for a token this host does not know. The caller refuses rather than falling back
    /// to a different base: quietly answering a question that was not asked is how a review
    /// screen ends up showing the wrong changes under the right title.
    pub(crate) fn from_wire(token: &str) -> Option<Self> {
        match token {
            "uncommitted" => Some(Self::Uncommitted),
            "branch" => Some(Self::Branch),
            _ => None,
        }
    }
}

/// One base this workspace can actually be measured against, and the words the reader picks it
/// by. The label names the branch because "vs main" is the whole question the reader is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiffBaseOption {
    pub(crate) base: DiffBase,
    pub(crate) label: String,
}

/// The branch a merge would target.
///
/// `origin/HEAD` first, because that is the remote's own statement of its default rather than a
/// guess; the local names are the fallback for a repository with no remote at all. Every one of
/// these is a ref this host chose — none of it comes from the phone.
async fn base_branch(git: &Path, workdir: &Path) -> Option<String> {
    let remote = run_git(git, workdir, &["rev-parse", "--abbrev-ref", "origin/HEAD"]).await;
    if let Ok(out) = remote
        && out.success()
    {
        let name = String::from_utf8(out.stdout)
            .unwrap_or_default()
            .trim()
            .to_owned();
        // A repository whose origin/HEAD is unset can echo the symbolic name straight back.
        if !name.is_empty() && name != "origin/HEAD" {
            return Some(name);
        }
    }
    for candidate in ["main", "master"] {
        let found = run_git(
            git,
            workdir,
            &["rev-parse", "--verify", "--quiet", candidate],
        )
        .await;
        if matches!(&found, Ok(out) if out.success()) {
            return Some(candidate.to_owned());
        }
    }
    None
}

/// Where this branch left its base, and what that base is called.
///
/// `None` means there is no useful branch diff to offer: no base branch, or the merge base *is*
/// `HEAD`, which is what being on the base branch looks like. Both are reasons not to put the
/// option on screen at all rather than to show one that is always empty.
async fn branch_merge_base(git: &Path, workdir: &Path) -> Option<(String, String)> {
    let branch = base_branch(git, workdir).await?;
    let merge_base = run_git(git, workdir, &["merge-base", branch.as_str(), "HEAD"])
        .await
        .ok()?;
    if !merge_base.success() {
        return None;
    }
    let merge_base = String::from_utf8(merge_base.stdout).ok()?.trim().to_owned();
    if merge_base.is_empty() {
        return None;
    }
    let head = run_git(git, workdir, &["rev-parse", "HEAD"]).await.ok()?;
    if !head.success() {
        return None;
    }
    if String::from_utf8(head.stdout).ok()?.trim() == merge_base {
        return None;
    }
    Some((merge_base, branch))
}

/// Every base the reader may choose here, in the order they should see them.
///
/// `Uncommitted` is unconditional: "nothing uncommitted" is an answer the reader wants, not an
/// absence to hide. `Branch` appears only when it would show something.
pub(crate) async fn available_bases(workdir: &Path) -> Vec<DiffBaseOption> {
    let mut options = vec![DiffBaseOption {
        base: DiffBase::Uncommitted,
        label: "Uncommitted".to_owned(),
    }];
    let Some(git) = resolve_git() else {
        return options;
    };
    if let Some((_, branch)) = branch_merge_base(&git, workdir).await {
        // `origin/` is noise to a reader who is asking "against what": the branch name is the answer.
        let shown = branch.strip_prefix("origin/").unwrap_or(&branch);
        options.push(DiffBaseOption {
            base: DiffBase::Branch,
            label: if shown.len() <= 256 {
                format!("vs {shown}")
            } else {
                "Branch changes".to_owned()
            },
        });
    }
    options
}

/// Counts cover every enumerated untracked file. Omitted names are a bounded sample for
/// display only. The difference between total, shown and named is always available to the UI.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffCoverage {
    pub new_files_total: u32,
    pub new_files_shown: u32,
    pub omitted_names: Vec<String>,
}

impl DiffCoverage {
    const MAX_OMITTED_NAMES: usize = 32;
    const MAX_ENCODED_NAMES: usize = 1536;

    fn record_omission(&mut self, name: &[u8], bytes_left: &mut usize) {
        if self.omitted_names.len() == Self::MAX_OMITTED_NAMES || name.len() > *bytes_left {
            return;
        }
        let mut display = String::new();
        for chunk in name.utf8_chunks() {
            for ch in chunk.valid().chars() {
                display.extend(ch.escape_debug());
            }
            for byte in chunk.invalid() {
                use std::fmt::Write;
                write!(display, "\\x{byte:02x}").expect("writing to String");
            }
        }
        let encoded_bytes = serde_json::to_vec(&display)
            .expect("string serialization")
            .len()
            + usize::from(!self.omitted_names.is_empty());
        if encoded_bytes <= *bytes_left {
            *bytes_left -= encoded_bytes;
            self.omitted_names.push(display);
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct GitDiff {
    pub patch: String,
    pub coverage: DiffCoverage,
}

pub(crate) async fn diff(workdir: &Path, base: DiffBase) -> Result<GitDiff, GitDiffError> {
    match base {
        DiffBase::Uncommitted => uncommitted_diff(workdir).await,
        DiffBase::Branch => Ok(GitDiff {
            patch: branch_diff(workdir).await?,
            coverage: DiffCoverage::default(),
        }),
    }
}

/// --show-toplevel fails for a bare repository or a directory outside any worktree.
/// Use the root for every Git read, even when the terminal is inside a nested directory.
pub(super) async fn open_work_tree(workdir: &Path) -> Result<(PathBuf, PathBuf), GitDiffError> {
    let git = resolve_git().ok_or(GitDiffError::GitUnavailable)?;
    if !workdir.is_dir() {
        return Err(GitDiffError::NotARepository);
    }
    let top = run_git(&git, workdir, &["rev-parse", "--show-toplevel"]).await?;
    if !top.success() {
        return Err(GitDiffError::NotARepository);
    }
    let bytes = top.stdout.strip_suffix(b"\n").ok_or(GitDiffError::Failed)?;
    let root = PathBuf::from(OsStr::from_bytes(bytes));
    if !root.is_absolute() {
        return Err(GitDiffError::Failed);
    }
    Ok((git, root))
}

/// Every commit on this branch that its base branch does not have, as one patch.
///
/// Untracked and uncommitted work is deliberately absent: none of it is part of what a merge
/// would bring, and this base exists to answer "what am I about to merge".
async fn branch_diff(workdir: &Path) -> Result<String, GitDiffError> {
    let (git, root) = open_work_tree(workdir).await?;
    let workdir = root.as_path();
    let Some((merge_base, _)) = branch_merge_base(&git, workdir).await else {
        // This is only offered when it resolves, so arriving here means the branch moved under
        // the reader between enumerating and asking, or Git failed to establish it.
        return Err(GitDiffError::Failed);
    };
    let out = run_git(
        &git,
        workdir,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            merge_base.as_str(),
            "HEAD",
        ],
    )
    .await?;
    if out.truncated {
        return Err(GitDiffError::TooLarge);
    }
    if !out.success() || out.had_diagnostics {
        return Err(GitDiffError::Failed);
    }
    String::from_utf8(out.stdout).map_err(|_| GitDiffError::Failed)
}

/// The base every uncommitted change is measured against: `HEAD` normally, the empty tree when
/// nothing has been committed yet.
async fn diff_base(git: &Path, workdir: &Path) -> &'static str {
    match run_git(git, workdir, &["rev-parse", "--verify", "HEAD"]).await {
        Ok(out) if out.success() => "HEAD",
        _ => EMPTY_TREE,
    }
}

/// Untracked, non-ignored files rendered as whole-file additions.
///
/// `git diff` alone does not show them, and an agent's new files are exactly what the reader
/// wants to see. The honest way to include them is `--no-index` against `/dev/null`, one call
/// per file — the alternative, `--intent-to-add`, writes to the index, and this feature never
/// mutates the worktree on the phone's behalf.
async fn append_untracked(
    git: &Path,
    root: &Path,
    review: &mut GitDiff,
) -> Result<(), GitDiffError> {
    let listed = run_git(
        git,
        root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )
    .await?;
    if listed.truncated {
        return Err(GitDiffError::TooLarge);
    }
    if !listed.success()
        || listed.had_diagnostics
        || (!listed.stdout.is_empty() && !listed.stdout.ends_with(&[0]))
    {
        return Err(GitDiffError::Failed);
    }

    // Each entry includes at least one byte and a NUL in the 1 MiB listing, so u32 is ample.
    let mut sample_bytes = DiffCoverage::MAX_ENCODED_NAMES - 2; // JSON brackets
    for name in listed
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        review.coverage.new_files_total += 1;
        if review.coverage.new_files_total as usize <= MAX_UNTRACKED_FILES
            && let Ok(name) = std::str::from_utf8(name)
            && let Some(text) =
                new_file_patch(git, root, name, MAX_DIFF_BYTES - review.patch.len()).await
        {
            review.patch.push_str(&text);
            review.coverage.new_files_shown += 1;
        } else {
            review.coverage.record_omission(name, &mut sample_bytes);
        }
    }
    Ok(())
}

async fn new_file_patch(git: &Path, root: &Path, name: &str, remaining: usize) -> Option<String> {
    // Git lists an embedded untracked repository as a single directory ending in "/".
    // --no-index compares /dev/null with its namesake inside a directory, so its patch
    // could represent an unrelated file named "null" while appearing to cover the entry.
    if remaining == 0 || name.ends_with('/') {
        return None;
    }
    let out = run_git(
        git,
        root,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-index",
            "--",
            "/dev/null",
            // --no-index still interprets a literal "-" as stdin after the options.
            if name == "-" { "./-" } else { name },
        ],
    )
    .await
    .ok()?;
    // --no-index exits one for a difference. A failing or capped process may have emitted a
    // valid-looking prefix; never append any of its bytes.
    if out.exit_code != Some(1)
        || out.had_diagnostics
        || out.truncated
        || out.stdout.is_empty()
        || out.stdout.len() > remaining
    {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// Every uncommitted change in `workdir`, as one patch: staged and unstaged tracked changes
/// against the base, then untracked files as additions.
async fn uncommitted_diff(workdir: &Path) -> Result<GitDiff, GitDiffError> {
    let (git, root) = open_work_tree(workdir).await?;
    let workdir = root.as_path();

    let base = diff_base(&git, workdir).await;
    let tracked = run_git(
        &git,
        workdir,
        &["diff", "--no-ext-diff", "--no-textconv", "--no-color", base],
    )
    .await?;
    if tracked.truncated {
        return Err(GitDiffError::TooLarge);
    }
    if !tracked.success() || tracked.had_diagnostics {
        return Err(GitDiffError::Failed);
    }
    // A patch the renderer cannot accept is not a patch. Spec 008 §5.2: no lossy replacement,
    // because a review that looks authoritative and is not is the worst outcome here.
    let mut review = GitDiff {
        patch: String::from_utf8(tracked.stdout).map_err(|_| GitDiffError::Failed)?,
        coverage: DiffCoverage::default(),
    };
    append_untracked(&git, workdir, &mut review).await?;
    Ok(review)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn git_repo() -> Option<(tempfile::TempDir, PathBuf)> {
        let git = resolve_git()?;
        let temp = tempfile::tempdir().ok()?;
        let root = temp.path().canonicalize().ok()?;
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.email", "spike@example.invalid"],
            vec!["config", "user.name", "Spike"],
        ] {
            run_git(&git, &root, &args).await.ok()?;
        }
        Some((temp, root))
    }

    #[tokio::test]
    async fn a_directory_outside_any_repository_is_refused() {
        let temp = tempfile::tempdir().expect("temp");
        // A bare temp dir is not inside a work tree, and must not be reported as an empty diff:
        // "no changes" and "not a repository" are different answers to the reader.
        let outcome = uncommitted_diff(temp.path()).await;
        if resolve_git().is_some() {
            assert_eq!(outcome, Err(GitDiffError::NotARepository));
        }
    }

    #[tokio::test]
    async fn an_unborn_repository_shows_its_first_file_against_the_empty_tree() {
        let Some((_temp, root)) = git_repo().await else {
            return;
        };
        let git = resolve_git().expect("git");
        std::fs::write(root.join("first.txt"), "hello\n").expect("write");
        run_git(&git, &root, &["add", "first.txt"])
            .await
            .expect("add");

        // Nothing is committed, so HEAD does not resolve; the empty-tree base is what makes
        // this a diff rather than a git error.
        let patch = uncommitted_diff(&root).await.expect("diff").patch;
        assert!(patch.contains("first.txt"), "names the file: {patch}");
        assert!(patch.contains("+hello"), "shows the addition: {patch}");
    }

    #[tokio::test]
    async fn untracked_files_appear_as_additions_and_ignored_ones_do_not() {
        let Some((_temp, root)) = git_repo().await else {
            return;
        };
        let git = resolve_git().expect("git");
        std::fs::write(root.join("tracked.txt"), "one\n").expect("write");
        run_git(&git, &root, &["add", "tracked.txt"])
            .await
            .expect("add");
        run_git(&git, &root, &["commit", "-q", "-m", "first"])
            .await
            .expect("commit");

        std::fs::write(root.join(".gitignore"), "secret.txt\n").expect("write");
        std::fs::write(root.join("secret.txt"), "do not show\n").expect("write");
        std::fs::write(root.join("new.txt"), "brand new\n").expect("write");
        std::fs::write(root.join("tracked.txt"), "one\ntwo\n").expect("write");

        let patch = uncommitted_diff(&root).await.expect("diff").patch;
        assert!(patch.contains("+two"), "tracked edit is present: {patch}");
        assert!(
            patch.contains("new.txt"),
            "untracked file is present: {patch}"
        );
        assert!(
            patch.contains("+brand new"),
            "its content is present: {patch}"
        );
        // Not `contains("secret.txt")`: .gitignore is itself untracked, so its own added line
        // spells that name. What must never appear is the ignored file's diff or its contents.
        assert!(
            !patch.contains("diff --git a/secret.txt"),
            "an ignored file must never be diffed: {patch}"
        );
        assert!(
            !patch.contains("do not show"),
            "an ignored file's contents must never leak: {patch}"
        );
    }

    #[tokio::test]
    async fn a_clean_repository_produces_an_empty_patch_not_an_error() {
        let Some((_temp, root)) = git_repo().await else {
            return;
        };
        let git = resolve_git().expect("git");
        std::fs::write(root.join("only.txt"), "settled\n").expect("write");
        run_git(&git, &root, &["add", "only.txt"])
            .await
            .expect("add");
        run_git(&git, &root, &["commit", "-q", "-m", "first"])
            .await
            .expect("commit");

        // Clean is a state the reader is shown, not a failure (Spec 008 §2.1).
        assert_eq!(uncommitted_diff(&root).await, Ok(GitDiff::default()));
    }

    #[tokio::test]
    async fn an_oversized_untracked_file_has_no_partial_patch_and_does_not_hide_later_files() {
        let (_temp, root, git) = repo_on_main().await.expect("real Git");
        let oversize = root.join("oversize.txt");
        std::fs::write(&oversize, vec![b'x'; MAX_DIFF_BYTES * 2]).unwrap();

        // The child is still producing data when we reach the cap. This path used to wait
        // on its full stdout pipe to the command deadline, or return an incomplete prefix.
        let out = run_git(
            &git,
            &root,
            &[
                "diff",
                "--no-ext-diff",
                "--no-index",
                "--",
                "/dev/null",
                "oversize.txt",
            ],
        )
        .await
        .unwrap();
        assert!(out.truncated);
        assert!(out.stdout.is_empty());

        let only = uncommitted_diff(&root).await.unwrap();
        assert!(only.patch.is_empty());
        assert_eq!(only.coverage.new_files_total, 1);
        assert_eq!(only.coverage.new_files_shown, 0);
        assert_eq!(only.coverage.omitted_names, ["oversize.txt"]);
        std::fs::write(root.join("small.txt"), "included\n").unwrap();
        let mixed = uncommitted_diff(&root).await.unwrap();
        assert!(mixed.patch.contains("+included"));
        assert!(!mixed.patch.contains("oversize.txt"));
        assert_eq!(mixed.coverage.new_files_total, 2);
        assert_eq!(mixed.coverage.new_files_shown, 1);
        assert_eq!(mixed.coverage.omitted_names, ["oversize.txt"]);
    }

    #[tokio::test]
    async fn cumulative_patch_budget_keeps_whole_files_and_failed_enumeration_refuses_coverage() {
        let (_temp, root, git) = repo_on_main().await.expect("real Git");
        let block = vec![b'a'; 600 * 1024];
        std::fs::write(root.join("a.txt"), &block).unwrap();
        std::fs::write(root.join("b.txt"), &block).unwrap();
        std::fs::write(root.join("c.txt"), "still fits\n").unwrap();
        let review = uncommitted_diff(&root).await.unwrap();
        assert!(review.patch.len() <= MAX_DIFF_BYTES);
        assert!(review.patch.contains("a.txt"));
        assert!(!review.patch.contains("b.txt"));
        assert!(review.patch.contains("+still fits"));
        assert_eq!(review.coverage.new_files_total, 3);
        assert_eq!(review.coverage.new_files_shown, 2);
        assert_eq!(review.coverage.omitted_names, ["b.txt"]);

        let elsewhere = tempfile::tempdir().unwrap();
        let error = append_untracked(&git, elsewhere.path(), &mut GitDiff::default()).await;
        assert_eq!(error, Err(GitDiffError::Failed));
    }

    #[tokio::test]
    async fn embedded_untracked_repositories_are_named_without_diffing_an_unrelated_child() {
        let (_temp, root, git) = repo_on_main().await.expect("real Git");
        let embedded = root.join("embedded");
        std::fs::create_dir(&embedded).unwrap();
        assert!(
            run_git(&git, &embedded, &["init", "-q"])
                .await
                .unwrap()
                .success()
        );
        std::fs::write(embedded.join("null"), "unrelated content\n").unwrap();
        let review = uncommitted_diff(&root).await.unwrap();
        assert!(review.patch.is_empty());
        assert_eq!(review.coverage.new_files_total, 1);
        assert_eq!(review.coverage.new_files_shown, 0);
        assert_eq!(review.coverage.omitted_names, ["embedded/"]);
    }

    #[tokio::test]
    async fn a_nested_cwd_includes_siblings_renames_and_literal_dash_content() {
        let (_temp, root, git) = repo_on_main().await.expect("real Git");
        std::fs::create_dir(root.join("subdir")).unwrap();
        std::fs::write(root.join("-"), "literal dash contents\n").unwrap();
        assert!(
            run_git(&git, &root, &["mv", "base.txt", "renamed.txt"])
                .await
                .unwrap()
                .success()
        );
        let review = uncommitted_diff(&root.join("subdir")).await.unwrap();
        assert_eq!(review.coverage.new_files_total, 1);
        assert_eq!(review.coverage.new_files_shown, 1);
        assert!(review.coverage.omitted_names.is_empty());
        assert!(review.patch.contains("+literal dash contents"));
        assert!(review.patch.contains("rename from base.txt"));
        assert!(review.patch.contains("rename to renamed.txt"));
    }

    #[tokio::test]
    async fn untracked_non_utf8_content_is_named_without_inserting_a_partial_patch() {
        let (_temp, root, _git) = repo_on_main().await.expect("real Git");
        std::fs::write(root.join("bad\ncontent"), b"a\xffb\n").unwrap();
        let review = uncommitted_diff(&root).await.unwrap();
        assert!(review.patch.is_empty());
        assert_eq!(review.coverage.new_files_total, 1);
        assert_eq!(review.coverage.new_files_shown, 0);
        assert_eq!(review.coverage.omitted_names, [r"bad\ncontent"]);
    }

    // APFS rejects invalid UTF-8 at creation. Linux can enumerate such a file from real Git.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_non_utf8_filename_has_an_escaped_display_name() {
        let (_temp, root, _git) = repo_on_main().await.expect("real Git");
        std::fs::write(
            root.join(OsStr::from_bytes(b"mixed-\xff")),
            b"valid content\n",
        )
        .unwrap();
        let review = uncommitted_diff(&root).await.unwrap();
        assert!(review.patch.is_empty());
        assert_eq!(review.coverage.new_files_total, 1);
        assert_eq!(review.coverage.new_files_shown, 0);
        assert_eq!(review.coverage.omitted_names, [r"mixed-\xff"]);
    }

    #[test]
    fn omitted_name_sample_obeys_entry_and_encoded_byte_budgets() {
        let mut coverage = DiffCoverage::default();
        let mut remaining = DiffCoverage::MAX_ENCODED_NAMES - 2;
        for i in 0..70 {
            coverage.record_omission(format!("x-{i}").as_bytes(), &mut remaining);
        }
        assert_eq!(
            coverage.omitted_names.len(),
            DiffCoverage::MAX_OMITTED_NAMES
        );
        let mut coverage = DiffCoverage::default();
        let mut remaining = DiffCoverage::MAX_ENCODED_NAMES - 2;
        let long = [b'\\'; 120];
        for _ in 0..40 {
            coverage.record_omission(&long, &mut remaining);
        }
        assert!(coverage.omitted_names.len() < DiffCoverage::MAX_OMITTED_NAMES);
        assert!(
            serde_json::to_vec(&coverage.omitted_names).unwrap().len()
                <= DiffCoverage::MAX_ENCODED_NAMES
        );
    }

    /// A repository on `main` with one commit, which is where both base tests start.
    async fn repo_on_main() -> Option<(tempfile::TempDir, PathBuf, PathBuf)> {
        let (temp, root) = git_repo().await?;
        let git = resolve_git()?;
        std::fs::write(root.join("base.txt"), "settled\n").ok()?;
        run_git(&git, &root, &["add", "base.txt"]).await.ok()?;
        run_git(&git, &root, &["commit", "-q", "-m", "first"])
            .await
            .ok()?;
        // Named explicitly: `init.defaultBranch` varies by machine, and the label under test
        // is the branch's own name.
        run_git(&git, &root, &["branch", "-M", "main"]).await.ok()?;
        Some((temp, root, git))
    }

    #[tokio::test]
    async fn a_branch_shows_what_a_merge_would_bring_and_nothing_uncommitted() {
        let Some((_temp, root, git)) = repo_on_main().await else {
            return;
        };
        run_git(&git, &root, &["checkout", "-q", "-b", "feature"])
            .await
            .expect("branch");
        std::fs::write(root.join("shipped.txt"), "committed work\n").expect("write");
        run_git(&git, &root, &["add", "shipped.txt"])
            .await
            .expect("add");
        run_git(&git, &root, &["commit", "-q", "-m", "second"])
            .await
            .expect("commit");
        // Present in the worktree but not in any commit, so not part of a merge.
        std::fs::write(root.join("scratch.txt"), "not committed\n").expect("write");
        std::fs::write(root.join("base.txt"), "settled\nedited\n").expect("write");

        let options = available_bases(&root).await;
        assert!(
            options
                .iter()
                .any(|option| option.base == DiffBase::Branch && option.label == "vs main"),
            "the branch base is offered and names main: {options:?}"
        );

        let patch = diff(&root, DiffBase::Branch)
            .await
            .expect("branch diff")
            .patch;
        assert!(
            patch.contains("shipped.txt"),
            "the commit is there: {patch}"
        );
        assert!(patch.contains("+committed work"), "its content: {patch}");
        // The whole point of this base: uncommitted work is not what a merge would bring, and
        // showing it here would tell the reader a merge carries changes it does not.
        assert!(
            !patch.contains("scratch.txt"),
            "untracked work is not part of a merge: {patch}"
        );
        assert!(
            !patch.contains("+edited"),
            "uncommitted edits are not part of a merge: {patch}"
        );

        // And the other base still answers its own question.
        let uncommitted = diff(&root, DiffBase::Uncommitted)
            .await
            .expect("uncommitted")
            .patch;
        assert!(uncommitted.contains("+edited"), "the edit: {uncommitted}");
        assert!(
            uncommitted.contains("scratch.txt"),
            "the new file: {uncommitted}"
        );
    }

    #[tokio::test]
    async fn the_base_branch_itself_offers_no_branch_comparison() {
        let Some((_temp, root, _git)) = repo_on_main().await else {
            return;
        };
        // On `main` the merge base is HEAD, so "vs main" would be permanently empty. An option
        // that can only ever say "no changes" is worse than no option.
        let options = available_bases(&root).await;
        assert!(
            options.iter().all(|option| option.base != DiffBase::Branch),
            "no branch base on the base branch: {options:?}"
        );
        assert!(
            options
                .iter()
                .any(|option| option.base == DiffBase::Uncommitted),
            "uncommitted is always offered: {options:?}"
        );
    }

    #[tokio::test]
    async fn an_unknown_base_token_is_not_silently_read_as_another_one() {
        assert_eq!(
            DiffBase::from_wire("uncommitted"),
            Some(DiffBase::Uncommitted)
        );
        assert_eq!(DiffBase::from_wire("branch"), Some(DiffBase::Branch));
        // The refusal matters more than the mapping: a token this host cannot honour must not
        // resolve to a base that happens to be nearby.
        assert_eq!(DiffBase::from_wire("HEAD~1"), None);
        assert_eq!(DiffBase::from_wire(""), None);
    }

    #[tokio::test]
    async fn a_repository_config_pager_or_external_diff_cannot_take_effect() {
        let Some((_temp, root)) = git_repo().await else {
            return;
        };
        let git = resolve_git().expect("git");
        std::fs::write(root.join("file.txt"), "one\n").expect("write");
        run_git(&git, &root, &["add", "file.txt"])
            .await
            .expect("add");
        run_git(&git, &root, &["commit", "-q", "-m", "first"])
            .await
            .expect("commit");

        // A hostile checkout sets these in its own config and waits for someone to run git in
        // it. If either took effect the output would be the program's, not a patch.
        run_git(&git, &root, &["config", "core.pager", "false"])
            .await
            .expect("config");
        run_git(&git, &root, &["config", "diff.external", "/bin/false"])
            .await
            .expect("config");
        std::fs::write(root.join("file.txt"), "one\ntwo\n").expect("write");

        let patch = uncommitted_diff(&root).await.expect("diff").patch;
        assert!(patch.contains("+two"), "still a real patch: {patch}");
    }
}
