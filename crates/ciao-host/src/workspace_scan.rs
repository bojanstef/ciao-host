//! Git-repository discovery for the managed-session workspace list.
//!
//! Spec 006 §7.3 derived the workspace list from managed records alone, so the first session in
//! any directory had to be started from the host CLI. This closes that: the daemon finds the
//! projects already on disk, and the phone can start in one without a laptop.
//!
//! Deliberately not a filesystem browser. A browser needs paths on the wire, a descent UI, and an
//! answer to "this directory has 300 entries"; a repository list needs none of those, because a
//! checkout is the unit people actually start an agent in. Paths never leave the host either way:
//! the caller hashes each one into the same keyed opaque ID a record would have produced.

use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

/// Directories never descended into. Everything hidden is already skipped, which covers
/// `.Trash`, `.cache`, and the rest; these are the unhidden trees worth naming.
///
/// The media three are not about size. Opening `~/Pictures` or `~/Music` on macOS is what asks
/// for Photos and Media Library access, so descending them turned a project list into two
/// permission prompts on a Mac the person asking is not sitting at. Nobody keeps a checkout in a
/// photo library, so this costs nothing and removes two of the five dialogs a fresh host raised.
const SKIPPED_DIRECTORIES: &[&str] = &["Library", "node_modules", "Pictures", "Music", "Movies"];

/// How deep below home a checkout is still found: `~/a/b/c` yes, `~/a/b/c/d` no. Deep enough for
/// the common `~/code/org/project`, shallow enough that the sweep stays bounded on a wide home.
const MAX_DEPTH: usize = 3;

/// Hard ceiling on directories opened, so a pathological tree costs a bounded number of syscalls
/// rather than an unbounded pause in the daemon. Repository pruning means a normal home spends a
/// small fraction of this.
const MAX_VISITS: usize = 2_000;

/// Matches the protocol's own workspace-list cap; returning more would only be truncated later.
const MAX_RESULTS: usize = 64;

/// What one walk of home found, and whether it was allowed to see all of it.
///
/// `denied` exists because a refused directory is silent: `read_dir` fails, the walk carries on,
/// and the result is a shorter list that looks like a complete one. On macOS that is the normal
/// outcome of having once clicked Deny on the Desktop or Documents prompt, and the person then
/// sees a project list with their work missing and nothing saying why.
#[derive(Debug, Default)]
pub(crate) struct WorkspaceScan {
    pub(crate) paths: Vec<PathBuf>,
    pub(crate) denied: bool,
}

/// Every git checkout under `home`, most recently touched first.
///
/// ponytail: rescanned per call rather than cached. The phone asks once when the New Agent sheet
/// opens, a warm scan of a normal home is a few milliseconds, and a cache would need invalidation
/// for the one case it helps. Cache it if a home is ever slow enough to notice.
pub(crate) fn discover_git_workspaces(home: &Path) -> WorkspaceScan {
    let mut found: Vec<(SystemTime, PathBuf)> = Vec::new();
    let mut stack = vec![(home.to_path_buf(), 0usize)];
    let mut visits = 0usize;
    let mut denied = false;
    while let Some((directory, depth)) = stack.pop() {
        if visits >= MAX_VISITS {
            break;
        }
        visits += 1;
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                // Only permission is reported. A directory that vanished mid-walk is not
                // something the person can act on, and saying "approve access" about it would
                // send them to a settings pane that has nothing to fix.
                denied |= error.kind() == std::io::ErrorKind::PermissionDenied;
                continue;
            }
        };
        for entry in entries.flatten() {
            // `file_type` does not follow symlinks, so a symlinked directory is neither
            // descended nor reported. That loses the occasional linked code directory and buys
            // immunity from cycles and from a link that leads off the machine.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with('.') || SKIPPED_DIRECTORIES.contains(&name) {
                continue;
            }
            let path = entry.path();
            // `exists` rather than `is_dir`: a worktree and a submodule carry `.git` as a file,
            // and both are places you would start an agent.
            let marker = path.join(".git");
            if marker.exists() {
                // A checkout is a workspace and never a container of them. Descending would walk
                // the whole tree to find nothing, and a subdirectory of a checkout is not a
                // separate project.
                found.push((touched_at(&marker), path));
                continue;
            }
            if depth + 1 < MAX_DEPTH {
                stack.push((path, depth + 1));
            }
        }
    }
    found.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    found.truncate(MAX_RESULTS);
    WorkspaceScan {
        paths: found.into_iter().map(|(_, path)| path).collect(),
        denied,
    }
}

/// Recency signal for ranking.
///
/// ponytail: the mtime of `.git` itself. Git renames a new index into place on every add and
/// commit, which updates the directory's mtime, so this tracks work rather than the top-level
/// directory's mtime, which a deep edit never touches. Its ceiling is that a long read-only
/// session looks idle; walk refs or the reflog if that ever reads wrong.
fn touched_at(marker: &Path) -> SystemTime {
    fs::metadata(marker)
        .and_then(|metadata| metadata.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn repo(root: &Path, relative: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.join(".git")).unwrap();
    }

    #[test]
    fn finds_checkouts_and_skips_what_it_should() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path();
        repo(home, "project");
        repo(home, "code/org/deep");
        // Depth 4: past the ceiling.
        repo(home, "code/org/too/far");
        // Inside a checkout: not a separate workspace.
        repo(home, "project/vendored");
        repo(home, ".config/dotfiles");
        repo(home, "Library/Caches/thing");
        repo(home, "node_modules/package");
        // The media trees are skipped to avoid provoking the Photos and Media Library prompts,
        // so anything inside them is out of reach even when it is a real checkout.
        repo(home, "Pictures/Photos Library.photoslibrary/repo");
        repo(home, "Music/project");
        repo(home, "Movies/project");
        // A plain directory is not a workspace.
        fs::create_dir_all(home.join("Documents/notes")).unwrap();

        let found = discover_git_workspaces(home);

        assert!(!found.denied, "nothing here refuses to be read");
        let mut names: Vec<_> = found
            .paths
            .iter()
            .map(|path| {
                path.strip_prefix(home)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["code/org/deep".to_owned(), "project".to_owned()]
        );
    }

    /// Worktree-style `.git` files, so the mtime can be set through `File` rather than by
    /// reaching for a crate to touch a directory. The scan treats both forms the same.
    fn worktree(root: &Path, relative: &str, modified: SystemTime) {
        let path = root.join(relative);
        fs::create_dir_all(&path).unwrap();
        let marker = fs::File::create(path.join(".git")).unwrap();
        marker.set_modified(modified).unwrap();
    }

    #[test]
    fn ranks_most_recently_touched_first() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path();
        // Explicit times: creation order is not a guarantee at filesystem timestamp resolution.
        worktree(
            home,
            "older",
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        );
        worktree(
            home,
            "newer",
            SystemTime::UNIX_EPOCH + Duration::from_secs(2_000),
        );

        let found = discover_git_workspaces(home);

        assert_eq!(found.paths, vec![home.join("newer"), home.join("older")]);
    }

    #[test]
    fn a_missing_home_is_an_empty_list_not_a_failure() {
        let found = discover_git_workspaces(Path::new("/nonexistent/ciao-scan"));
        assert!(found.paths.is_empty());
        // Absent is not refused: a home that is not there says nothing about permissions, and
        // telling someone to approve access to it would be advice they cannot act on.
        assert!(!found.denied);
    }

    /// The macOS failure this was built for: `read_dir` on a folder the daemon was denied returns
    /// an error and the walk keeps going, so a partial list is indistinguishable from a complete
    /// one unless the refusal is carried out with it.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_refuses_to_be_read_is_reported_not_hidden() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let home = home.path();
        repo(home, "visible");
        let refused = home.join("refused");
        fs::create_dir_all(&refused).unwrap();
        fs::set_permissions(&refused, fs::Permissions::from_mode(0o000)).unwrap();

        let found = discover_git_workspaces(home);

        // Restored before any assertion can unwind past it, or the tempdir cannot be removed.
        fs::set_permissions(&refused, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(found.denied, "a refused directory must be reported");
        assert_eq!(
            found.paths,
            vec![home.join("visible")],
            "what could be read is still returned"
        );
    }
}
