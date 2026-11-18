use super::digest::Sha256;
use super::{Architecture, Backend, MAX_IMAGE, MAX_PROTOCOL, Snapshot, Transaction};
use nix::libc;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
};

use crate::MAX_PROBE_TRANSACTIONS as MAX_TRANSACTIONS;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    transaction: Transaction,
    helper: Backend,
    device: u64,
    inode: u64,
}

fn nonce_valid(nonce: &str) -> bool {
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn private_directory(path: &Path) -> Option<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    // SAFETY: geteuid has no preconditions.
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7777 != 0o700 {
        return None;
    }
    Some(file)
}
fn new_directory(path: &Path) -> Option<()> {
    fs::DirBuilder::new().mode(0o700).create(path).ok()
}
fn regular(file: &File, mode: u32) -> Option<std::fs::Metadata> {
    let meta = file.metadata().ok()?;
    // SAFETY: geteuid has no preconditions.
    (meta.is_file()
        && meta.nlink() == 1
        && meta.uid() == unsafe { libc::geteuid() }
        && meta.mode() & 0o7777 == mode)
        .then_some(meta)
}
fn root(transaction: &Transaction) -> Option<(File, File)> {
    if !nonce_valid(&transaction.nonce) || !transaction.root.is_absolute() {
        return None;
    }
    let parent = transaction.root.parent()?;
    let _parent = private_directory(parent)?;
    if transaction.root.file_name()? != "native-codex-image-v1" {
        return None;
    }
    match fs::DirBuilder::new().mode(0o700).create(&transaction.root) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return None,
    }
    let directory = private_directory(&transaction.root)?;
    // Security static validation assumes a local immutable filesystem, not a network/FUSE view.
    // SAFETY: fstatfs writes one initialized structure for the open directory descriptor.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut stat) } != 0
        || stat.f_flags & libc::MNT_LOCAL as u32 == 0
    {
        return None;
    }
    let name: Vec<u8> = stat
        .f_fstypename
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as u8)
        .collect();
    if name != b"apfs" {
        return None;
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(transaction.root.join("lock"))
        .ok()?;
    regular(&lock, 0o600)?;
    // SAFETY: valid held fd, advisory lock is released on drop. Blocking only in alarm-armed helper.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return None;
    }
    Some((directory, lock))
}
fn location(transaction: &Transaction) -> PathBuf {
    transaction.root.join(&transaction.nonce)
}
fn helper() -> Option<Backend> {
    let pid = std::process::id();
    Some(Backend {
        pid,
        identity: crate::native_identity(pid)?,
    })
}
fn write_record(transaction: &Transaction, directory: &File, first: bool) -> Option<()> {
    let metadata = directory.metadata().ok()?;
    let record = Record {
        transaction: transaction.clone(),
        helper: helper()?,
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let destination = location(transaction).join("owner.json");
    let temporary = location(transaction).join("owner.next");
    let mut file = options
        .open(if first { &destination } else { &temporary })
        .ok()?;
    regular(&file, 0o600)?;
    let bytes = serde_json::to_vec(&record).ok()?;
    file.write_all(&bytes).ok()?;
    file.sync_all().ok()?;
    drop(file);
    if !first {
        fs::rename(temporary, destination).ok()?;
    }
    Some(())
}
fn record(transaction: &Transaction, directory: &File) -> Option<Record> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(location(transaction).join("owner.json"))
        .ok()?;
    if regular(&file, 0o600)?.len() > MAX_PROTOCOL as u64 {
        return None;
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_PROTOCOL as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_PROTOCOL {
        return None;
    }
    let record: Record = serde_json::from_slice(&bytes).ok()?;
    let meta = directory.metadata().ok()?;
    (record.transaction == *transaction
        && record.device == meta.dev()
        && record.inode == meta.ino())
    .then_some(record)
}
fn gone(backend: &Backend) -> bool {
    if let Some(identity) = crate::native_identity(backend.pid) {
        return identity != backend.identity;
    }
    let Ok(pid) = i32::try_from(backend.pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // An inspection error is NOT proof of death. ESRCH or a different positive identity is.
    // SAFETY: signal 0 only queries existence; never signals a reused PID.
    unsafe {
        libc::kill(pid, 0) != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
}
fn prune(transaction: &Transaction) -> Option<usize> {
    let entries: Vec<_> = fs::read_dir(&transaction.root)
        .ok()?
        .take(MAX_TRANSACTIONS + 2)
        .collect();
    if entries.len() > MAX_TRANSACTIONS + 1 {
        return None;
    }
    let mut count = 0;
    for entry in entries {
        let entry = entry.ok()?;
        if entry.file_name() == "lock" {
            continue;
        }
        count += 1;
        let Some(nonce) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !nonce_valid(&nonce) {
            continue;
        }
        let candidate = Transaction {
            nonce,
            ..transaction.clone()
        };
        let path = location(&candidate);
        let Some(directory) = private_directory(&path) else {
            continue;
        };
        // Owner is recovered only from a bounded regular marker in a private owned directory.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path.join("owner.json"));
        let Ok(file) = file else {
            continue;
        };
        if regular(&file, 0o600).is_none() {
            continue;
        }
        let mut bytes = Vec::new();
        if file
            .take(MAX_PROTOCOL as u64 + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() > MAX_PROTOCOL
        {
            continue;
        }
        let Ok(marker) = serde_json::from_slice::<Record>(&bytes) else {
            continue;
        };
        if marker.transaction.root != transaction.root
            || marker.transaction.nonce != candidate.nonce
        {
            continue;
        }
        if record(&marker.transaction, &directory).is_some()
            && gone(&marker.transaction.owner)
            && gone(&marker.helper)
            && fs::remove_dir_all(&path).is_ok()
        {
            count -= 1;
        }
    }
    // Unknown/incomplete artifacts are retained and count against the cap; never delete guesses.
    Some(count)
}
fn enter(transaction: &Transaction) -> Option<(File, File, File)> {
    let (root, lock) = root(transaction)?;
    let directory = private_directory(&location(transaction))?;
    let previous = record(transaction, &directory)?;
    if !gone(&previous.helper) || !transaction.owner.valid() {
        return None;
    }
    write_record(transaction, &directory, false)?;
    Some((root, lock, directory))
}
fn environment_directories(transaction: &Transaction) -> (PathBuf, PathBuf) {
    let directory = location(transaction);
    (directory.join("home"), directory.join("tmp"))
}
fn image_path(transaction: &Transaction) -> PathBuf {
    location(transaction).join("codex")
}
fn open_image(transaction: &Transaction) -> Option<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(image_path(transaction))
        .ok()
}
fn digest(file: &mut File) -> Option<String> {
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut hasher = Sha256::new()?;
    let mut bytes = [0u8; 128 * 1024];
    let mut total = 0u64;
    loop {
        let size = file.read(&mut bytes).ok()?;
        if size == 0 {
            break;
        }
        total = total.checked_add(size as u64)?;
        if total > MAX_IMAGE {
            return None;
        }
        hasher.update(&bytes[..size])?;
    }
    hasher.finish()
}
fn matching_file(snapshot: &Snapshot) -> Option<File> {
    let image = open_image(&snapshot.transaction)?;
    let before = regular(&image, 0o500)?;
    if before.len() == 0
        || before.len() > MAX_IMAGE
        || before.dev() != snapshot.device
        || before.ino() != snapshot.inode
        || before.len() != snapshot.size
    {
        return None;
    }
    Some(image)
}
fn matches(snapshot: &Snapshot) -> Option<File> {
    let mut image = matching_file(snapshot)?;
    let before = regular(&image, 0o500)?;
    if digest(&mut image)? != snapshot.sha256 {
        return None;
    }
    let after = regular(&image, 0o500)?;
    (before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec())
    .then_some(image)
}

pub(super) fn prepare(transaction: Transaction, backend: Backend) -> Option<Snapshot> {
    if !transaction.owner.valid() || !backend.valid() {
        return None;
    }
    let (_root, _lock) = root(&transaction)?;
    if prune(&transaction)? >= MAX_TRANSACTIONS {
        return None;
    }
    let directory_path = location(&transaction);
    new_directory(&directory_path)?;
    let directory = private_directory(&directory_path)?;
    write_record(&transaction, &directory, true)?;
    let path = super::security::candidate_path(backend.pid)?;
    if fs::canonicalize(&path).ok()? != path {
        return None;
    }
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
        .ok()?;
    let before = source.metadata().ok()?;
    if !before.is_file() || before.nlink() != 1 || before.len() == 0 || before.len() > MAX_IMAGE {
        return None;
    }
    // Source signing information is only a candidate. It also rejects bundle association before
    // relocation can flatten it. Path changes during this lookup can only cause later refusal:
    // copy bytes still come exclusively from the already held source descriptor.
    let code_hash = super::security::candidate_hash(&path)?;
    // Exclusive directory-relative regular-file creation. No writable copy fd survives validation.
    // SAFETY: directory is a held private directory fd; fixed NUL-terminated basename and mode.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"codex".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: newly owned fd, exactly one File takes ownership.
    let mut destination = unsafe { File::from_raw_fd(fd) };
    regular(&destination, 0o600)?;
    let mut total = 0u64;
    let mut bytes = [0u8; 128 * 1024];
    loop {
        let size = source.read(&mut bytes).ok()?;
        if size == 0 {
            break;
        }
        total = total.checked_add(size as u64)?;
        if total > MAX_IMAGE {
            return None;
        }
        destination.write_all(&bytes[..size]).ok()?;
    }
    if total != before.len() {
        return None;
    }
    destination
        .set_permissions(fs::Permissions::from_mode(0o500))
        .ok()?;
    destination.sync_all().ok()?;
    drop(destination);
    drop(source);
    let mut image = open_image(&transaction)?;
    let meta = regular(&image, 0o500)?;
    thin_arm64(&mut image)?;
    let sha256 = digest(&mut image)?;
    if super::security::candidate_hash(&image_path(&transaction))? != code_hash {
        return None;
    }
    super::security::validate_copy(&image_path(&transaction), &code_hash)?;
    super::dynamic(&backend, &code_hash)?;
    let (home, temporary) = environment_directories(&transaction);
    new_directory(&home)?;
    new_directory(&temporary)?;
    let snapshot = Snapshot {
        transaction,
        backend,
        architecture: Architecture::Arm64,
        code_hash,
        device: meta.dev(),
        inode: meta.ino(),
        size: meta.len(),
        sha256,
    };
    matching_file(&snapshot)?;
    Some(snapshot)
}

pub(super) fn execute(snapshot: &Snapshot) -> Option<()> {
    let (_root, lock, _directory) = enter(&snapshot.transaction)?;
    let _image = matches(snapshot)?;
    super::security::validate_copy(&image_path(&snapshot.transaction), &snapshot.code_hash)?;
    super::dynamic(&snapshot.backend, &snapshot.code_hash)?;
    matching_file(snapshot)?;
    let (home, temporary) = environment_directories(&snapshot.transaction);
    let _home = private_directory(&home)?;
    let _temporary = private_directory(&temporary)?;
    // No root lock across vendor execution. Marker binds this same PID through exec, so pruning
    // refuses while it lives even after daemon death. Every fd above has CLOEXEC.
    drop(lock);
    crate::reset_probe_alarm(super::HELPER_SECONDS)?;
    let _error = std::process::Command::new(image_path(&snapshot.transaction))
        .arg("--version")
        .current_dir(&home)
        .env_clear()
        .env("HOME", &home)
        .env("CODEX_HOME", &home)
        // Release Codex refuses executable aliases when CODEX_HOME is under TMPDIR.
        // Separate private siblings satisfy that rule without relaxing stderr/launch checks.
        .env("TMPDIR", &temporary)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin")
        .exec();
    None
}
pub(super) fn finish(snapshot: &Snapshot) -> Option<()> {
    let (_root, _lock, _directory) = enter(&snapshot.transaction)?;
    let _image = matches(snapshot)?;
    super::dynamic(&snapshot.backend, &snapshot.code_hash)?;
    matching_file(snapshot)?;
    Some(())
}
pub(super) fn cleanup(transaction: &Transaction) -> Option<()> {
    let (_root, _lock) = root(transaction)?;
    let path = location(transaction);
    if !path.try_exists().ok()? {
        return Some(());
    }
    let directory = private_directory(&path)?;
    let marker = record(transaction, &directory)?;
    if !gone(&marker.helper) {
        return None;
    }
    // No recursive deletion outside the uniquely named, uid/mode/inode-checked transaction.
    fs::remove_dir_all(path).ok()
}

/// Restrict relocation to thin native bare executables with embedded signatures and system-only
/// absolute dependencies. No fat slices, Rosetta, rpaths, loader-relative dependencies or plugins.
fn thin_arm64(file: &mut File) -> Option<()> {
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut header = [0u8; 32];
    file.read_exact(&mut header).ok()?;
    let word = |b: &[u8], i| -> Option<u32> {
        Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
    };
    if word(&header, 0)? != 0xfeedfacf
        || word(&header, 4)? != 0x0100000c
        || word(&header, 8)? != 0
        || word(&header, 12)? != 2
    {
        return None;
    }
    let count = word(&header, 16)? as usize;
    let size = word(&header, 20)? as usize;
    if count == 0 || count > 1024 || size > 1024 * 1024 || size < count.checked_mul(8)? {
        return None;
    }
    let mut commands = vec![0; size];
    file.read_exact(&mut commands).ok()?;
    validate_commands(&commands, count, file.metadata().ok()?.len())
}
fn validate_commands(commands: &[u8], count: usize, file_size: u64) -> Option<()> {
    let word = |b: &[u8], i| -> Option<u32> {
        Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
    };
    let mut offset = 0usize;
    let mut signatures = 0;
    let mut loaders = 0;
    for _ in 0..count {
        let rest = commands.get(offset..)?;
        let kind = word(rest, 0)?;
        let size = word(rest, 4)? as usize;
        if size < 8 || !size.is_multiple_of(8) {
            return None;
        }
        let command = rest.get(..size)?;
        match kind {
            0x1d => {
                signatures += 1;
                if size != 16 {
                    return None;
                }
                let start = u64::from(word(command, 8)?);
                let len = u64::from(word(command, 12)?);
                if len == 0
                    || start < 32 + commands.len() as u64
                    || start.checked_add(len)? != file_size
                {
                    return None;
                }
            }
            0xe | 0xc | 0x80000018 | 0x8000001f | 0x20 | 0x80000023 => {
                let start = word(command, 8)? as usize;
                if start < if kind == 0xe { 12 } else { 24 } {
                    return None;
                }
                let name = command.get(start..)?;
                let end = name.iter().position(|b| *b == 0)?;
                let name = std::str::from_utf8(&name[..end]).ok()?;
                if kind == 0xe {
                    loaders += 1;
                    if name != "/usr/lib/dyld" {
                        return None;
                    }
                } else if !(name.starts_with("/usr/lib/")
                    || name.starts_with("/System/Library/Frameworks/"))
                    || name.split('/').any(|s| s == ".." || s == ".")
                {
                    return None;
                }
            }
            // Qualified metadata/link-edit commands. Refuse unknown commands, dyld environment
            // directives and rpaths rather than accidentally admitting another relocation model.
            0x19 | 0x80000022 | 0x2 | 0xb | 0x1b | 0x32 | 0x2a | 0x80000028 | 0x26 | 0x29
            | 0x80000033 | 0x80000034 | 0x24 => (),
            _ => return None,
        }
        offset = offset.checked_add(size)?;
    }
    (offset == commands.len() && signatures == 1 && loaders == 1).then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_home_is_not_under_the_temporary_directory() {
        let transaction = Transaction {
            root: PathBuf::from("/private/run"),
            nonce: "a".repeat(32),
            owner: Backend {
                pid: 1,
                identity: String::new(),
            },
        };
        let (home, temporary) = environment_directories(&transaction);
        assert_eq!(home.parent(), temporary.parent());
        assert!(!home.starts_with(&temporary));
        assert!(!temporary.starts_with(&home));
    }
    fn fixture_commands() -> Vec<u8> {
        let mut loader = vec![0u8; 32];
        loader[..4].copy_from_slice(&0xeu32.to_le_bytes());
        loader[4..8].copy_from_slice(&32u32.to_le_bytes());
        loader[8..12].copy_from_slice(&12u32.to_le_bytes());
        loader[12..26].copy_from_slice(b"/usr/lib/dyld\0");
        let mut signature = vec![0u8; 16];
        signature[..4].copy_from_slice(&0x1du32.to_le_bytes());
        signature[4..8].copy_from_slice(&16u32.to_le_bytes());
        signature[8..12].copy_from_slice(&80u32.to_le_bytes());
        signature[12..16].copy_from_slice(&32u32.to_le_bytes());
        loader.extend(signature);
        loader
    }
    #[test]
    fn qualified_commands_and_signature_bounds() {
        let valid = fixture_commands();
        assert!(validate_commands(&valid, 2, 112).is_some());
        assert!(validate_commands(&valid, 2, 111).is_none());
        assert!(validate_commands(&valid, 1, 112).is_none());
        let mut duplicate = valid.clone();
        duplicate.extend_from_slice(&valid[32..]);
        assert!(validate_commands(&duplicate, 3, 112).is_none());
        for kind in [0x8000001cu32, 0x27, 0xfffffff0] {
            let mut bytes = valid.clone();
            bytes[..4].copy_from_slice(&kind.to_le_bytes());
            assert!(validate_commands(&bytes, 2, 112).is_none());
        }
        for size in [0u32, 7, 9, 31, 4096] {
            let mut bytes = valid.clone();
            bytes[4..8].copy_from_slice(&size.to_le_bytes());
            assert!(validate_commands(&bytes, 2, 112).is_none());
        }
    }
    #[test]
    fn malformed_commands_and_duplicate_signatures_refuse() {
        assert!(validate_commands(&[], 1, 0).is_none());
        assert!(validate_commands(&[0; 8], 1, 8).is_none());
        for length in 0..128 {
            assert!(validate_commands(&vec![255; length], 1, 512).is_none());
        }
        assert!(!nonce_valid("../codex"));
        assert!(nonce_valid(&"a".repeat(32)));
    }
}
