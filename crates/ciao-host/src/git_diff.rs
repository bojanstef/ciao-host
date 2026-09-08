//! Spec 008 spike — the uncommitted diff of one workspace, as one patch string.
//!
//! Deliberately not Spec 008 §5.3's snapshot. There is no manifest, no per-file record, no
//! opaque file IDs, no omission reasons, and no snapshot lifetime: this produces the bytes
//! `git diff` produces so the renderer can be judged against a real repository. The structured
//! snapshot is the thing to build once the renderer decision is settled.
//!
//! What is *not* provisional is the process policy, because loosening it later is harder than
//! writing it now: a fixed absolute binary, fixed argv, no shell, the PTY broker's cleaned
//! environment, a deadline, and a hard output cap. Repository config is never modified, and
//! stderr never leaves this module — a refusal must not become a filesystem probe.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

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

struct GitOutput {
    success: bool,
    stdout: Vec<u8>,
    truncated: bool,
}

/// One fixed git invocation. `-C` carries the directory rather than `current_dir`, so the
/// cleaned environment's own working directory stays untouched and the argv is the whole story.
async fn run_git(git: &Path, workdir: &Path, args: &[&str]) -> Result<GitOutput, GitDiffError> {
    let mut command = Command::new(git);
    command
        .arg("-C")
        .arg(workdir)
        // Config on the command line, so a repository's own .git/config cannot reintroduce a
        // pager, an external diff driver, or a textconv filter that would run arbitrary
        // programs on the owner's machine because a phone asked to look at a diff.
        .args(["--no-pager", "-c", "core.pager=cat", "-c", "diff.external="])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    apply_clean_process_environment(&mut command).map_err(|_| GitDiffError::Failed)?;

    let mut child = command.spawn().map_err(|_| GitDiffError::GitUnavailable)?;
    let mut stdout = child.stdout.take().ok_or(GitDiffError::Failed)?;

    let collected = timeout(GIT_TIMEOUT, async {
        // One byte past the cap, so "exactly at the cap" and "over it" are distinguishable
        // rather than both reading as a full buffer.
        let mut buffer = Vec::new();
        // On the heap, not the stack. An `async fn` holds its locals in its future, so a 64 KiB
        // array here is 64 KiB in every future that awaits a git call — and those nest several
        // deep by the time the download stream holds one. It overflowed a debug thread stack.
        let mut chunk = vec![0_u8; 64 * 1024];
        let mut truncated = false;
        loop {
            match stdout.read(&mut chunk).await {
                Ok(0) => break,
                Ok(count) => {
                    if buffer.len() + count > MAX_DIFF_BYTES {
                        truncated = true;
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..count]);
                }
                Err(_) => return Err(GitDiffError::Failed),
            }
        }
        let status = child.wait().await.map_err(|_| GitDiffError::Failed)?;
        Ok(GitOutput {
            success: status.success(),
            stdout: buffer,
            truncated,
        })
    })
    .await
    .map_err(|_| GitDiffError::Timeout)??;

    Ok(collected)
}

/// True when `workdir` is inside a non-bare work tree. Two questions, because a bare repository
/// answers the first one "true" and has nothing to diff.
async fn is_work_tree(git: &Path, workdir: &Path) -> bool {
    let inside = run_git(git, workdir, &["rev-parse", "--is-inside-work-tree"]).await;
    let inside = matches!(&inside, Ok(out) if out.success && out.stdout.starts_with(b"true"));
    if !inside {
        return false;
    }
    match run_git(git, workdir, &["rev-parse", "--is-bare-repository"]).await {
        Ok(out) => out.success && out.stdout.starts_with(b"false"),
        Err(_) => false,
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
    if let Ok(out) = remote {
        let name = String::from_utf8(out.stdout)
            .unwrap_or_default()
            .trim()
            .to_owned();
        // A repository whose origin/HEAD is unset can echo the symbolic name straight back.
        if out.success && !name.is_empty() && name != "origin/HEAD" {
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
        if matches!(&found, Ok(out) if out.success) {
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
    if !merge_base.success {
        return None;
    }
    let merge_base = String::from_utf8(merge_base.stdout).ok()?.trim().to_owned();
    if merge_base.is_empty() {
        return None;
    }
    let head = run_git(git, workdir, &["rev-parse", "HEAD"]).await.ok()?;
    if !head.success {
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
            label: format!("vs {shown}"),
        });
    }
    options
}

/// The patch for one chosen base.
pub(crate) async fn diff(workdir: &Path, base: DiffBase) -> Result<String, GitDiffError> {
    match base {
        DiffBase::Uncommitted => uncommitted_diff(workdir).await,
        DiffBase::Branch => branch_diff(workdir).await,
    }
}

/// The guard both bases share: git exists, and this is somewhere with a work tree to read.
async fn open_work_tree(workdir: &Path) -> Result<PathBuf, GitDiffError> {
    let git = resolve_git().ok_or(GitDiffError::GitUnavailable)?;
    if !workdir.is_dir() {
        return Err(GitDiffError::NotARepository);
    }
    if !is_work_tree(&git, workdir).await {
        return Err(GitDiffError::NotARepository);
    }
    Ok(git)
}

/// Every commit on this branch that its base branch does not have, as one patch.
///
/// Untracked and uncommitted work is deliberately absent: none of it is part of what a merge
/// would bring, and this base exists to answer "what am I about to merge".
async fn branch_diff(workdir: &Path) -> Result<String, GitDiffError> {
    let git = open_work_tree(workdir).await?;
    let Some((merge_base, _)) = branch_merge_base(&git, workdir).await else {
        // This is only offered when it resolves, so arriving here means the branch moved under
        // the reader between enumerating and asking. Empty is the honest answer, not an error.
        return Ok(String::new());
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
    if !out.success {
        return Err(GitDiffError::Failed);
    }
    String::from_utf8(out.stdout).map_err(|_| GitDiffError::Failed)
}

/// The base every uncommitted change is measured against: `HEAD` normally, the empty tree when
/// nothing has been committed yet.
async fn diff_base(git: &Path, workdir: &Path) -> &'static str {
    match run_git(git, workdir, &["rev-parse", "--verify", "HEAD"]).await {
        Ok(out) if out.success => "HEAD",
        _ => EMPTY_TREE,
    }
}

/// Untracked, non-ignored files rendered as whole-file additions.
///
/// `git diff` alone does not show them, and an agent's new files are exactly what the reader
/// wants to see. The honest way to include them is `--no-index` against `/dev/null`, one call
/// per file — the alternative, `--intent-to-add`, writes to the index, and this feature never
/// mutates the worktree on the phone's behalf.
async fn untracked_patch(git: &Path, workdir: &Path, budget: &mut usize) -> String {
    let listed = run_git(
        git,
        workdir,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )
    .await;
    let Ok(listed) = listed else {
        return String::new();
    };
    if !listed.success {
        return String::new();
    }

    let mut patch = String::new();
    for name in listed
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .take(MAX_UNTRACKED_FILES)
    {
        // Non-UTF-8 names are skipped rather than lossily converted: a name the renderer cannot
        // round-trip is worse than an omission, and Spec 008 §5.2 owns the escaped-name design.
        let Ok(name) = std::str::from_utf8(name) else {
            continue;
        };
        // `--no-index` exits 1 precisely when there is a difference, which is the whole point,
        // so success is not the check here — output is.
        let Ok(out) = run_git(
            git,
            workdir,
            &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                "--no-index",
                "--",
                "/dev/null",
                name,
            ],
        )
        .await
        else {
            continue;
        };
        let Ok(text) = String::from_utf8(out.stdout) else {
            continue;
        };
        if text.is_empty() || text.len() > *budget {
            continue;
        }
        *budget -= text.len();
        patch.push_str(&text);
    }
    patch
}

/// Every uncommitted change in `workdir`, as one patch: staged and unstaged tracked changes
/// against the base, then untracked files as additions.
pub(crate) async fn uncommitted_diff(workdir: &Path) -> Result<String, GitDiffError> {
    let git = open_work_tree(workdir).await?;

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
    if !tracked.success {
        return Err(GitDiffError::Failed);
    }
    // A patch the renderer cannot accept is not a patch. Spec 008 §5.2: no lossy replacement,
    // because a review that looks authoritative and is not is the worst outcome here.
    let mut patch = String::from_utf8(tracked.stdout).map_err(|_| GitDiffError::Failed)?;

    let mut budget = MAX_DIFF_BYTES.saturating_sub(patch.len());
    patch.push_str(&untracked_patch(&git, workdir, &mut budget).await);
    Ok(patch)
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
        let patch = uncommitted_diff(&root).await.expect("diff");
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

        let patch = uncommitted_diff(&root).await.expect("diff");
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
        assert_eq!(uncommitted_diff(&root).await, Ok(String::new()));
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

        let patch = diff(&root, DiffBase::Branch).await.expect("branch diff");
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
            .expect("uncommitted");
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

        let patch = uncommitted_diff(&root).await.expect("diff");
        assert!(patch.contains("+two"), "still a real patch: {patch}");
    }
}
