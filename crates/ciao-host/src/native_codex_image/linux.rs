//! Linux custodian: keep the existing native-image cache and its held FD inside a killable
//! helper. The daemon, never this custodian, directly owns the fixed-version launcher PID.
use super::{CodexVersion, NativeArchitecture, VerifiedCodexImage, supervision};
use crate::storage::CiaoPaths;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::oneshot,
    time::Instant,
};

#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;

const FLAG: &str = "--ciao-native-codex-linux-v1";
const CAP: usize = 4096;
const ALARM: u32 = ciao_native_process::PROBE_ALARM_SECONDS;
const MAX_TRANSACTIONS: usize = ciao_native_process::MAX_PROBE_TRANSACTIONS;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Holder {
    pid: u32,
    identity: String,
}
impl Holder {
    async fn current(&self) -> bool {
        self.pid > 0
            && self.identity.len() <= 128
            && crate::process::terminal_identity(self.pid).await.as_deref() == Some(&self.identity)
    }
    async fn own() -> Option<Self> {
        let pid = std::process::id();
        Some(Self {
            pid,
            identity: crate::process::terminal_identity(pid).await?,
        })
    }
    async fn gone(&self) -> bool {
        if let Some(now) = crate::process::terminal_identity(self.pid).await {
            return now != self.identity;
        }
        let Ok(pid) = i32::try_from(self.pid) else {
            return false;
        };
        pid > 0
            && nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None)
                == Err(nix::errno::Errno::ESRCH)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImageIdentity {
    backend: Holder,
    stamp: String,
    architecture: NativeArchitecture,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    run_dir: PathBuf,
    nonce: String,
    owner: Holder,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
enum Request {
    Observe {
        transaction: Transaction,
        backend: Holder,
    },
    Launch {
        transaction: Transaction,
        image: ImageIdentity,
        custodian: Holder,
        fd: u32,
    },
    Revalidate {
        image: ImageIdentity,
    },
    Cleanup {
        transaction: Transaction,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", deny_unknown_fields)]
enum Frame {
    Probe {
        image: ImageIdentity,
        custodian: Holder,
        fd: u32,
    },
    Done {
        image: ImageIdentity,
        version: String,
    },
    Valid {},
    Clean {},
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    transaction: Transaction,
    custodian: Holder,
    launcher: Option<Holder>,
    device: u64,
    inode: u64,
}

/// Called before the normal runtime/logger. No generic command or arbitrary executable mode.
pub fn helper_entry() -> Option<i32> {
    let mut args = std::env::args_os();
    args.next();
    if args.next().as_deref() != Some(std::ffi::OsStr::new(FLAG)) {
        return None;
    }
    if ciao_native_process::prepare_probe_helper(ALARM).is_none() {
        return Some(1);
    }
    let result = (|| {
        let text = args.next()?;
        let text = text.to_str()?;
        if text.len() > CAP || args.next().is_some() {
            return None;
        }
        let request: Request = serde_json::from_str(text).ok()?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?
            .block_on(dispatch(request))
    })();
    Some(if result.is_some() { 0 } else { 1 })
}
async fn dispatch(request: Request) -> Option<()> {
    match request {
        Request::Observe {
            transaction,
            backend,
        } => custody(transaction, backend).await,
        Request::Launch {
            transaction,
            image,
            custodian,
            fd,
        } => launch(transaction, image, custodian, fd).await,
        Request::Revalidate { image } => {
            current_image(&image).await?;
            emit(&Frame::Valid {})
        }
        Request::Cleanup { transaction } => {
            cleanup(&transaction).await?;
            emit(&Frame::Clean {})
        }
    }
}
fn emit(frame: &Frame) -> Option<()> {
    let mut bytes = serde_json::to_vec(frame).ok()?;
    if bytes.len() >= CAP {
        return None;
    }
    bytes.push(b'\n');
    std::io::stdout().write_all(&bytes).ok()?;
    std::io::stdout().flush().ok()
}
fn architecture(file: &File) -> Option<NativeArchitecture> {
    let meta = file.metadata().ok()?;
    if meta.len() == 0 || meta.len() > ciao_native_process::MAX_PROBE_IMAGE_BYTES {
        return None;
    }
    let mut header = [0; 20];
    file.read_exact_at(&mut header, 0).ok()?;
    if &header[..4] != b"\x7fELF" || header[4..7] != [2, 1, 1] {
        return None;
    }
    if ![2, 3].contains(&u16::from_le_bytes(header[16..18].try_into().ok()?)) {
        return None;
    }
    match u16::from_le_bytes(header[18..20].try_into().ok()?) {
        183 if cfg!(target_arch = "aarch64") => Some(NativeArchitecture::Arm64),
        62 if cfg!(target_arch = "x86_64") => Some(NativeArchitecture::X86_64),
        _ => None,
    }
}
async fn current_image(image: &ImageIdentity) -> Option<File> {
    if !image.backend.current().await {
        return None;
    }
    let path = crate::process::kernel_executable(image.backend.pid)?;
    let (file, stamp) = crate::hook_common::native_image_identity(&path).ok()?;
    if stamp != image.stamp
        || architecture(&file)? != image.architecture
        || !image.backend.current().await
    {
        return None;
    }
    Some(file)
}
async fn cached_held_version<F, Fut>(
    paths: &CiaoPaths,
    held: &File,
    probe: F,
) -> anyhow::Result<(String, bool)>
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<String>>,
{
    // One image transaction on hits AND misses: never let the cache independently reopen
    // /proc/backend/exe (A -> cached B -> A would otherwise borrow B's version for A).
    let reference = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
    crate::hook_common::cached_native_version(paths, &reference, probe).await
}
async fn custody(transaction: Transaction, backend: Holder) -> Option<()> {
    if !transaction.owner.current().await || !backend.current().await {
        return None;
    }
    let image_path = crate::process::kernel_executable(backend.pid)?;
    let (held, stamp) = crate::hook_common::native_image_identity(&image_path).ok()?;
    let image = ImageIdentity {
        backend,
        stamp,
        architecture: architecture(&held)?,
    };
    current_image(&image).await?;
    let custodian = Holder::own().await?;
    let mut paths = CiaoPaths::for_home("/");
    paths.run_dir = transaction.run_dir.clone();
    let request_image = image.clone();
    // Reuse the existing cache over our already-held image, not a second backend lookup.
    // The closure requests one daemon-owned version exec, never spawns a grandchild.
    let (version, _) = cached_held_version(&paths, &held, |path| async move {
        let result = async {
            create_home(&transaction, &custodian).await?;
            let prefix = format!("/proc/{}/fd/", std::process::id());
            let fd = path.to_str()?.strip_prefix(&prefix)?.parse::<u32>().ok()?;
            emit(&Frame::Probe {
                image: request_image,
                custodian,
                fd,
            })?;
            let mut bytes = Vec::new();
            tokio::io::stdin()
                .take(257)
                .read_to_end(&mut bytes)
                .await
                .ok()?;
            let version = CodexVersion::parse(&bytes)?;
            Some(version.as_str().to_owned())
        }
        .await;
        result.ok_or_else(|| anyhow::anyhow!("native image version refused"))
    })
    .await
    .ok()?;
    let version = CodexVersion::parse(format!("codex-cli {version}\n").as_bytes())?;
    current_image(&image).await?;
    // `held` remains alive until the final frame has been emitted; no inode reuse window.
    emit(&Frame::Done {
        image,
        version: version.as_str().to_owned(),
    })?;
    drop(held);
    Some(())
}
async fn launch(
    transaction: Transaction,
    image: ImageIdentity,
    custodian: Holder,
    fd: u32,
) -> Option<()> {
    if fd < 3 || !transaction.owner.current().await || !custodian.current().await {
        return None;
    }
    let _backend = current_image(&image).await?;
    let path = PathBuf::from(format!("/proc/{}/fd/{fd}", custodian.pid));
    let (held, stamp) = crate::hook_common::native_image_identity(&path).ok()?;
    if stamp != image.stamp
        || architecture(&held)? != image.architecture
        || !custodian.current().await
    {
        return None;
    }
    let (_root, lock) = root(&transaction)?;
    let mut owner = ownership(&transaction)?;
    if owner.custodian != custodian || owner.launcher.is_some() {
        return None;
    }
    owner.launcher = Some(Holder::own().await?);
    write_ownership(&transaction, &owner, false)?;
    let (home, temporary) = environment_directories(&transaction);
    private_dir(&home)?;
    private_dir(&temporary)?;
    drop(lock);
    ciao_native_process::reset_probe_alarm(ALARM)?;
    // Resolve only this helper's held ELF descriptor. No install-path re-open or PATH fallback.
    let _error = std::process::Command::new(format!("/proc/self/fd/{}", held.as_raw_fd()))
        .arg("--version")
        .current_dir(&home)
        .env_clear()
        .env("HOME", &home)
        .env("CODEX_HOME", &home)
        // Release Codex rejects CODEX_HOME beneath TMPDIR. Both are private siblings.
        .env("TMPDIR", &temporary)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .exec();
    None
}
fn private_dir(path: &Path) -> Option<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    (meta.is_dir()
        && meta.uid() == nix::unistd::Uid::effective().as_raw()
        && meta.mode() & 0o7777 == 0o700)
        .then_some(file)
}
fn root(transaction: &Transaction) -> Option<(File, File)> {
    if transaction.nonce.len() != 32
        || !transaction
            .nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    private_dir(&transaction.run_dir)?;
    let path = transaction.run_dir.join("native-codex-linux-v1");
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return None,
    }
    let directory = private_dir(&path)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path.join("lock"))
        .ok()?;
    let meta = lock.metadata().ok()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != nix::unistd::Uid::effective().as_raw()
        || meta.mode() & 0o7777 != 0o600
    {
        return None;
    }
    lock.lock().ok()?;
    Some((directory, lock))
}
fn home(transaction: &Transaction) -> PathBuf {
    transaction
        .run_dir
        .join("native-codex-linux-v1")
        .join(&transaction.nonce)
}
fn environment_directories(transaction: &Transaction) -> (PathBuf, PathBuf) {
    let directory = home(transaction);
    (directory.join("home"), directory.join("tmp"))
}
fn ownership(transaction: &Transaction) -> Option<Ownership> {
    let path = home(transaction);
    let directory = private_dir(&path)?;
    let meta = directory.metadata().ok()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path.join("owner.json"))
        .ok()?;
    let fm = file.metadata().ok()?;
    if !fm.is_file()
        || fm.nlink() != 1
        || fm.uid() != nix::unistd::Uid::effective().as_raw()
        || fm.mode() & 0o7777 != 0o600
        || fm.len() > CAP as u64
    {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(CAP as u64 + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() > CAP {
        return None;
    }
    let owner: Ownership = serde_json::from_slice(&bytes).ok()?;
    (owner.transaction == *transaction && owner.device == meta.dev() && owner.inode == meta.ino())
        .then_some(owner)
}
fn write_ownership(transaction: &Transaction, owner: &Ownership, first: bool) -> Option<()> {
    let path = home(transaction);
    let temporary = path.join(if first { "owner.json" } else { "owner.next" });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&temporary)
        .ok()?;
    file.write_all(&serde_json::to_vec(owner).ok()?).ok()?;
    file.sync_all().ok()?;
    drop(file);
    if !first {
        fs::rename(temporary, path.join("owner.json")).ok()?;
    }
    Some(())
}
async fn create_home(transaction: &Transaction, custodian: &Holder) -> Option<()> {
    let (_root, _lock) = root(transaction)?;
    let entries: Vec<_> = fs::read_dir(transaction.run_dir.join("native-codex-linux-v1"))
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
        // Read only bounded regular markers in owned directories; unknown paths consume capacity.
        let path = entry.path();
        if private_dir(&path).is_none() {
            continue;
        }
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path.join("owner.json"))
        else {
            continue;
        };
        let mut bytes = Vec::new();
        if file.take(CAP as u64 + 1).read_to_end(&mut bytes).is_err() || bytes.len() > CAP {
            continue;
        }
        let Ok(owner) = serde_json::from_slice::<Ownership>(&bytes) else {
            continue;
        };
        if owner.transaction.run_dir != transaction.run_dir
            || home(&owner.transaction) != path
            || ownership(&owner.transaction).is_none()
        {
            continue;
        }
        if owner.transaction.owner.gone().await
            && owner.custodian.gone().await
            && match &owner.launcher {
                Some(p) => p.gone().await,
                None => true,
            }
            && fs::remove_dir_all(path).is_ok()
        {
            count -= 1;
        }
    }
    if count >= MAX_TRANSACTIONS {
        return None;
    }
    let path = home(transaction);
    fs::DirBuilder::new().mode(0o700).create(&path).ok()?;
    let meta = private_dir(&path)?.metadata().ok()?;
    write_ownership(
        transaction,
        &Ownership {
            transaction: transaction.clone(),
            custodian: custodian.clone(),
            launcher: None,
            device: meta.dev(),
            inode: meta.ino(),
        },
        true,
    )?;
    let (home, temporary) = environment_directories(transaction);
    fs::DirBuilder::new().mode(0o700).create(home).ok()?;
    fs::DirBuilder::new().mode(0o700).create(temporary).ok()?;
    Some(())
}
async fn cleanup(transaction: &Transaction) -> Option<()> {
    let (_root, _lock) = root(transaction)?;
    if !home(transaction).try_exists().ok()? {
        return Some(());
    }
    let owner = ownership(transaction)?;
    if !owner.custodian.gone().await
        || match owner.launcher {
            Some(p) => !p.gone().await,
            None => false,
        }
    {
        return None;
    }
    fs::remove_dir_all(home(transaction)).ok()
}

fn spawn(executable: &Path, request: &Request, input: bool) -> Option<Child> {
    let text = serde_json::to_string(request).ok()?;
    if text.len() > CAP {
        return None;
    }
    Command::new(executable)
        .arg(FLAG)
        .arg(text)
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(if input { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false)
        .spawn()
        .ok()
}
async fn one(
    executable: &Path,
    request: &Request,
    deadline: Instant,
    cancellation: Option<&mut oneshot::Receiver<()>>,
) -> Option<Vec<u8>> {
    supervision::collect(
        spawn(executable, request, false)?,
        deadline,
        cancellation,
        CAP,
    )
    .await
}
/// First custodian frame is deliberately incremental; neither EOF nor a newline can bypass the
/// operation deadline. stderr is concurrently drained and any content refuses this protocol.
async fn first(
    child: &mut Child,
    deadline: Instant,
    cancel: &mut oneshot::Receiver<()>,
) -> Option<Frame> {
    let stdout = child.stdout.as_mut()?;
    let stderr = child.stderr.as_mut()?;
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    let mut errors = [0u8; 256];
    let mut err_open = true;
    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => return None,
            _ = &mut *cancel => return None,
            n = stderr.read(&mut errors), if err_open => match n { Ok(0) => err_open = false, _ => return None },
            n = stdout.read(&mut byte) => {
                if n.ok()? != 1 { return None; }
                if byte[0] == b'\n' { return serde_json::from_slice(&bytes).ok(); }
                bytes.push(byte[0]); if bytes.len() >= CAP { return None; }
            }
        }
    }
}
async fn observe_inner(
    executable: &Path,
    tx: &Transaction,
    backend: Holder,
    deadline: Instant,
    cancel: &mut oneshot::Receiver<()>,
) -> Option<VerifiedCodexImage> {
    let mut owned = Some(spawn(
        executable,
        &Request::Observe {
            transaction: tx.clone(),
            backend: backend.clone(),
        },
        true,
    )?);
    let result = async {
        let mut input = owned.as_mut()?.stdin.take()?;
        let initial = first(owned.as_mut()?, deadline, cancel).await?;
        let final_frame = match initial {
            Frame::Probe {
                image,
                custodian: holder,
                fd,
            } => {
                if image.backend != backend || Some(holder.pid) != owned.as_ref()?.id() {
                    return None;
                }
                let output = one(
                    executable,
                    &Request::Launch {
                        transaction: tx.clone(),
                        image,
                        custodian: holder,
                        fd,
                    },
                    deadline,
                    Some(cancel),
                )
                .await?;
                CodexVersion::parse(&output)?;
                tokio::time::timeout_at(deadline, async {
                    input.write_all(&output).await?;
                    input.shutdown().await
                })
                .await
                .ok()?
                .ok()?;
                drop(input);
                let output =
                    supervision::collect(owned.take()?, deadline, Some(cancel), CAP).await?;
                return verified(serde_json::from_slice::<Frame>(&output).ok()?, &backend);
            }
            done @ Frame::Done { .. } => done,
            _ => return None,
        };
        drop(input);
        // A cache hit still needs successful exit and no extra stdout/stderr after its one frame.
        let rest = supervision::collect(owned.take()?, deadline, Some(cancel), CAP).await?;
        if !rest.is_empty() {
            return None;
        }
        verified(final_frame, &backend)
    };
    let result = result.await;
    if let Some(mut child) = owned {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    result
}
fn verified(frame: Frame, backend: &Holder) -> Option<VerifiedCodexImage> {
    let Frame::Done { image, version } = frame else {
        return None;
    };
    if image.backend != *backend
        || image.stamp.len() != 32
        || !image.stamp.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let version = CodexVersion::parse(format!("codex-cli {version}\n").as_bytes())?;
    Some(VerifiedCodexImage {
        version,
        architecture: image.architecture,
        linux_identity: image,
    })
}

pub(super) async fn observe(
    paths: &CiaoPaths,
    pid: u32,
    identity: &str,
) -> Option<VerifiedCodexImage> {
    observe_using(paths, pid, identity, std::env::current_exe().ok()?).await
}

pub(super) async fn observe_using(
    paths: &CiaoPaths,
    pid: u32,
    identity: &str,
    executable: PathBuf,
) -> Option<VerifiedCodexImage> {
    let permit = supervision::OPERATIONS.try_acquire().ok()?;
    if !ciao_native_process::can_reap_probe_children() {
        return None;
    }
    if pid == 0 || identity.len() > 128 {
        return None;
    }
    let backend = Holder {
        pid,
        identity: identity.to_owned(),
    };
    let tx = Transaction {
        run_dir: paths.run_dir.clone(),
        nonce: format!("{:032x}", rand::random::<u128>()),
        owner: Holder::own().await?,
    };
    let (sender, mut cancel) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _permit = permit;
        let result = observe_inner(
            &executable,
            &tx,
            backend,
            Instant::now() + supervision::OPERATION_LIMIT,
            &mut cancel,
        )
        .await;
        let cleanup = one(
            &executable,
            &Request::Cleanup { transaction: tx },
            Instant::now() + Duration::from_secs(5),
            None,
        )
        .await;
        if matches!(
            cleanup.and_then(|b| serde_json::from_slice::<Frame>(&b).ok()),
            Some(Frame::Clean {})
        ) {
            result
        } else {
            None
        }
    });
    let result = tokio::time::timeout(supervision::OPERATION_LIMIT + Duration::from_secs(5), task)
        .await
        .ok()
        .and_then(Result::ok)
        .flatten();
    drop(sender);
    result
}
pub(super) async fn revalidate(
    _paths: &CiaoPaths,
    pid: u32,
    identity: &str,
    image: &VerifiedCodexImage,
) -> bool {
    let Ok(executable) = std::env::current_exe() else {
        return false;
    };
    revalidate_using(pid, identity, image, executable).await
}

pub(super) async fn revalidate_using(
    pid: u32,
    identity: &str,
    image: &VerifiedCodexImage,
    executable: PathBuf,
) -> bool {
    if !ciao_native_process::can_reap_probe_children()
        || image.linux_identity.backend.pid != pid
        || image.linux_identity.backend.identity != identity
    {
        return false;
    }
    let Ok(permit) = supervision::OPERATIONS.try_acquire() else {
        return false;
    };
    let request = Request::Revalidate {
        image: image.linux_identity.clone(),
    };
    let (sender, mut cancel) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _permit = permit;
        let output = one(
            &executable,
            &request,
            Instant::now() + supervision::OPERATION_LIMIT,
            Some(&mut cancel),
        )
        .await;
        matches!(
            output.and_then(|b| serde_json::from_slice::<Frame>(&b).ok()),
            Some(Frame::Valid {})
        )
    });
    let result = tokio::time::timeout(supervision::OPERATION_LIMIT, task)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false);
    drop(sender);
    result
}
