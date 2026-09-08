//! Merge-safe installation for Ciao's one owned Pi extension (Spec 005 §9.2).
//!
//! Pi discovers a standalone file in its documented global `extensions` directory. Ciao never
//! edits Pi settings, updates Pi/packages, or touches another extension.

use std::{
    env, fs,
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};

use crate::storage::{CiaoPaths, atomic_write_private, validate_private_file};

const EXTENSION_FILE_NAME: &str = "ciao-agent-session.ts";
const OWNERSHIP_MARKER: &str = "Ciao attached Agent Session bridge for Pi 0.81.1";
const MAX_EXTENSION_BYTES: u64 = 128 * 1024;
const EXTENSION_SOURCE: &str = include_str!("../../../integrations/pi/ciao-agent-session.ts");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiIntegrationStatus {
    NotInstalled,
    Installed,
    UpdateAvailable,
}

impl PiIntegrationStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotInstalled => "not installed",
            Self::Installed => "installed",
            Self::UpdateAvailable => "installed; update available",
        }
    }
}

pub fn install_pi_extension(paths: &CiaoPaths) -> Result<PiIntegrationStatus> {
    install_at(&pi_extension_path(paths)?)
}

pub fn uninstall_pi_extension(paths: &CiaoPaths) -> Result<bool> {
    uninstall_at(&pi_extension_path(paths)?)
}

pub fn pi_integration_status(paths: &CiaoPaths) -> Result<PiIntegrationStatus> {
    status_at(&pi_extension_path(paths)?)
}

/// Whether Pi itself is present for this user — the signal `ciao setup` uses to pre-select
/// integrations. Directory presence is the only honest probe; Pi has no version handshake here.
pub(crate) fn pi_detected(paths: &CiaoPaths) -> bool {
    pi_agent_dir(paths).is_ok_and(|dir| dir.exists())
}

fn pi_agent_dir(paths: &CiaoPaths) -> Result<PathBuf> {
    match env::var_os("PI_CODING_AGENT_DIR") {
        Some(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                bail!("PI_CODING_AGENT_DIR must be an absolute path");
            }
            Ok(path)
        }
        _ => Ok(paths.home.join(".pi/agent")),
    }
}

fn pi_extension_path(paths: &CiaoPaths) -> Result<PathBuf> {
    Ok(pi_agent_dir(paths)?
        .join("extensions")
        .join(EXTENSION_FILE_NAME))
}

fn install_at(target: &Path) -> Result<PiIntegrationStatus> {
    validate_embedded_source()?;
    let parent = target
        .parent()
        .ok_or_else(|| anyhow!("Pi extension target has no parent"))?;
    ensure_owned_directory(parent)?;

    let previous = read_existing_owned(target)?;
    if previous.as_deref() == Some(EXTENSION_SOURCE.as_bytes()) {
        fs::set_permissions(target, fs::Permissions::from_mode(0o600))
            .context("secure the Ciao Pi extension")?;
        validate_installed(target)?;
        return Ok(PiIntegrationStatus::Installed);
    }

    // A same-directory backup is visible only during replacement and covers only Ciao's file.
    // It is removed after validation; a failed write/validation restores it atomically.
    let backup = parent.join(format!(
        ".{EXTENSION_FILE_NAME}.backup.{}",
        std::process::id()
    ));
    if backup.exists() {
        let metadata =
            fs::symlink_metadata(&backup).context("inspect stale Pi extension backup")?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != current_uid()
        {
            bail!("refusing an unsafe stale Ciao Pi extension backup");
        }
        fs::remove_file(&backup).context("remove stale Ciao Pi extension backup")?;
    }
    if let Some(bytes) = &previous {
        atomic_write_private(&backup, bytes).context("back up the previous Ciao Pi extension")?;
    }

    let result = (|| -> Result<()> {
        atomic_write_private(target, EXTENSION_SOURCE.as_bytes())
            .context("install the Ciao Pi extension")?;
        validate_installed(target)
    })();
    if let Err(error) = result {
        if previous.is_some() && backup.exists() {
            let _ = fs::rename(&backup, target);
            let _ = File::open(parent).and_then(|directory| directory.sync_all());
        } else {
            let _ = fs::remove_file(target);
        }
        return Err(error.context("Ciao Pi extension installation was rolled back"));
    }
    if backup.exists() {
        fs::remove_file(&backup).context("remove Ciao Pi extension backup")?;
    }
    File::open(parent)?.sync_all()?;
    Ok(PiIntegrationStatus::Installed)
}

fn uninstall_at(target: &Path) -> Result<bool> {
    let Some(_) = read_existing_owned(target)? else {
        return Ok(false);
    };
    let parent = target
        .parent()
        .ok_or_else(|| anyhow!("Pi extension target has no parent"))?;
    fs::remove_file(target).context("remove the Ciao Pi extension")?;
    File::open(parent)?.sync_all()?;
    Ok(true)
}

fn status_at(target: &Path) -> Result<PiIntegrationStatus> {
    let Some(existing) = read_existing_owned(target)? else {
        return Ok(PiIntegrationStatus::NotInstalled);
    };
    if existing == EXTENSION_SOURCE.as_bytes() {
        validate_private_file(target).context("validate Ciao Pi extension security")?;
        Ok(PiIntegrationStatus::Installed)
    } else {
        Ok(PiIntegrationStatus::UpdateAvailable)
    }
}

fn ensure_owned_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).context("inspect Pi extensions directory")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("Pi extensions location must be a regular directory");
        }
        if metadata.uid() != current_uid() {
            bail!("Pi extensions directory belongs to another account");
        }
        // Preserve an existing Pi directory's mode instead of rewriting user configuration.
        return Ok(());
    }
    fs::create_dir_all(path).context("create Pi extensions directory")?;
    let metadata = fs::symlink_metadata(path).context("inspect new Pi extensions directory")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != current_uid() {
        bail!("new Pi extensions location failed validation");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .context("secure new Pi extensions directory")?;
    Ok(())
}

fn read_existing_owned(path: &Path) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect Ciao Pi extension"),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.uid() != current_uid() {
        bail!("refusing to replace an unsafe Pi extension entry");
    }
    if metadata.len() == 0 || metadata.len() > MAX_EXTENSION_BYTES {
        bail!("refusing to replace an unrecognized Pi extension entry");
    }
    let file = File::open(path).context("open existing Ciao Pi extension")?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MAX_EXTENSION_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read existing Ciao Pi extension")?;
    if bytes.len() as u64 > MAX_EXTENSION_BYTES
        || !String::from_utf8_lossy(&bytes).contains(OWNERSHIP_MARKER)
    {
        bail!("the Ciao Pi extension filename is occupied by a different file");
    }
    Ok(Some(bytes))
}

fn validate_embedded_source() -> Result<()> {
    if EXTENSION_SOURCE.is_empty()
        || EXTENSION_SOURCE.len() as u64 > MAX_EXTENSION_BYTES
        || !EXTENSION_SOURCE.contains(OWNERSHIP_MARKER)
        || EXTENSION_SOURCE.contains("ctx.ui.custom(")
        || EXTENSION_SOURCE.contains("onTerminalInput(")
        || EXTENSION_SOURCE.contains("child_process")
    {
        bail!("embedded Ciao Pi extension failed static validation");
    }
    Ok(())
}

fn validate_installed(path: &Path) -> Result<()> {
    validate_private_file(path).context("validate installed Ciao Pi extension security")?;
    let bytes = fs::read(path).context("read installed Ciao Pi extension for validation")?;
    if bytes != EXTENSION_SOURCE.as_bytes() {
        bail!("installed Ciao Pi extension does not match the validated source");
    }
    Ok(())
}

fn current_uid() -> u32 {
    nix::unistd::Uid::effective().as_raw()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn install_update_status_and_uninstall_are_idempotent_and_merge_safe() {
        let temporary = tempdir().unwrap();
        let extensions = temporary.path().join("agent/extensions");
        fs::create_dir_all(&extensions).unwrap();
        fs::set_permissions(&extensions, fs::Permissions::from_mode(0o755)).unwrap();
        let unrelated = extensions.join("other.ts");
        fs::write(&unrelated, "export default () => {};").unwrap();
        let target = extensions.join(EXTENSION_FILE_NAME);

        assert_eq!(
            status_at(&target).unwrap(),
            PiIntegrationStatus::NotInstalled
        );
        assert_eq!(install_at(&target).unwrap(), PiIntegrationStatus::Installed);
        assert_eq!(install_at(&target).unwrap(), PiIntegrationStatus::Installed);
        assert_eq!(status_at(&target).unwrap(), PiIntegrationStatus::Installed);
        assert_eq!(
            fs::metadata(&extensions).unwrap().permissions().mode() & 0o777,
            0o755,
            "an existing Pi directory mode must be preserved"
        );
        assert_eq!(
            fs::read_to_string(&unrelated).unwrap(),
            "export default () => {};"
        );

        let older =
            EXTENSION_SOURCE.replace("const BRIDGE_VERSION = 1;", "const BRIDGE_VERSION = 0;");
        fs::write(&target, older).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            status_at(&target).unwrap(),
            PiIntegrationStatus::UpdateAvailable
        );
        install_at(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), EXTENSION_SOURCE.as_bytes());

        assert!(uninstall_at(&target).unwrap());
        assert!(!uninstall_at(&target).unwrap());
        assert!(unrelated.exists());
    }

    #[test]
    fn foreign_files_and_symlinks_are_never_replaced_or_removed() {
        let temporary = tempdir().unwrap();
        let extensions = temporary.path().join("extensions");
        fs::create_dir_all(&extensions).unwrap();
        let target = extensions.join(EXTENSION_FILE_NAME);
        fs::write(&target, "foreign extension").unwrap();
        assert!(install_at(&target).is_err());
        assert!(uninstall_at(&target).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "foreign extension");

        fs::remove_file(&target).unwrap();
        let foreign = temporary.path().join("foreign.ts");
        fs::write(&foreign, EXTENSION_SOURCE).unwrap();
        symlink(&foreign, &target).unwrap();
        assert!(install_at(&target).is_err());
        assert!(uninstall_at(&target).is_err());
        assert!(target.is_symlink());
    }

    #[test]
    fn embedded_extension_has_a_small_fixed_command_and_no_ui_interception_surface() {
        validate_embedded_source().unwrap();
        assert!(EXTENSION_SOURCE.contains("\"prompt\""));
        assert!(EXTENSION_SOURCE.contains("\"steer\""));
        assert!(EXTENSION_SOURCE.contains("\"follow_up\""));
        assert!(EXTENSION_SOURCE.contains("\"interrupt\""));
        for forbidden in [
            "ctx.ui.custom(",
            "onTerminalInput(",
            "child_process",
            "setModel(",
            "setActiveTools(",
            "process.env.API",
        ] {
            assert!(!EXTENSION_SOURCE.contains(forbidden));
        }
    }
}
