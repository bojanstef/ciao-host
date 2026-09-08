//! Authenticated, bounded host presentation metadata.
//!
//! Values collected here are presentation-only. They are never logged, used as authority,
//! interpolated into commands, or copied into artifact metadata.

#[cfg(target_os = "macos")]
use std::process::Command;
use std::{
    fs::{self, File},
    io::{Read, Take},
    path::Path,
};

use anyhow::{Result, anyhow};
use iroh::EndpointId;

#[cfg(target_os = "linux")]
use crate::host_protocol::valid_host_metadata_token;
use crate::host_protocol::{HOST_PROTOCOL_VERSION, HostInfoResult, normalize_host_display_name};

const LOCAL_METADATA_FILE_CAP: u64 = 64 * 1024;
const NATIVE_NAME_OUTPUT_CAP: usize = 256;

/// Coarse platform token used in status output and install metadata.
pub(crate) fn platform_token() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unsupported"
    }
}

pub(crate) fn collect(endpoint_id: EndpointId) -> Result<HostInfoResult> {
    let display_name = platform_display_name().unwrap_or_else(|| {
        let short: String = endpoint_id.to_string().chars().take(10).collect();
        format!("Host {short}")
    });
    let architecture = normalized_architecture()?;
    let machine_token = machine_token();

    #[cfg(target_os = "macos")]
    let result = HostInfoResult {
        v: HOST_PROTOCOL_VERSION,
        display_name,
        platform: "macos".into(),
        distribution: None,
        distribution_version: None,
        architecture,
        machine_token,
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };

    #[cfg(target_os = "linux")]
    let result = {
        let (distribution, distribution_version) = linux_distribution();
        HostInfoResult {
            v: HOST_PROTOCOL_VERSION,
            display_name,
            platform: "linux".into(),
            distribution,
            distribution_version,
            architecture,
            machine_token,
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }
    };

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return Err(anyhow!("this Ciao host platform is unsupported"));

    result
        .validate()
        .map_err(|_| anyhow!("local host display metadata is invalid"))?;
    Ok(result)
}

/// Stable opaque machine identity surviving `ciao reset`: a truncated hash of the
/// platform machine identifier. The raw id never crosses the protocol boundary (systemd
/// documents machine-id as confidential; only a keyed/app-specific derivation may be
/// exposed) and an unreadable identifier degrades to no token rather than an error.
fn machine_token() -> Option<String> {
    raw_machine_identifier().map(|raw| derive_machine_token(&raw))
}

fn derive_machine_token(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ciao-machine-token-v1\0");
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(target_os = "macos")]
fn raw_machine_identifier() -> Option<String> {
    // `ioreg` is the platform-native hardware UUID accessor. Fixed argv, no shell; the
    // bounded output is scanned for the one quoted IOPlatformUUID value.
    let output = Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() as u64 > LOCAL_METADATA_FILE_CAP {
        return None;
    }
    let text = std::str::from_utf8(&output.stdout).ok()?;
    let line = text.lines().find(|line| line.contains("IOPlatformUUID"))?;
    let value = line.split('"').nth(3)?;
    (!value.is_empty() && value.len() <= NATIVE_NAME_OUTPUT_CAP).then(|| value.to_owned())
}

#[cfg(target_os = "linux")]
fn raw_machine_identifier() -> Option<String> {
    machine_id_file(Path::new("/etc/machine-id"))
        .or_else(|| machine_id_file(Path::new("/var/lib/dbus/machine-id")))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn raw_machine_identifier() -> Option<String> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn machine_id_file(path: &Path) -> Option<String> {
    let value = read_bounded_text(path)?;
    let id = value.lines().next()?.trim();
    (id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| id.to_ascii_lowercase())
}

fn normalized_architecture() -> Result<String> {
    match std::env::consts::ARCH {
        "aarch64" => Ok("aarch64".into()),
        "x86_64" => Ok("x86_64".into()),
        _ => Err(anyhow!(
            "this host architecture is not supported by Ciao alpha artifacts"
        )),
    }
}

#[cfg(target_os = "macos")]
fn platform_display_name() -> Option<String> {
    // `scutil` is the platform-native Computer Name accessor. Invocation is fixed argv, has no
    // shell, and its bounded output is accepted only after the shared display-name validator.
    let output = Command::new("/usr/sbin/scutil")
        .args(["--get", "ComputerName"])
        .output()
        .ok()?;
    if output.status.success() && output.stdout.len() <= NATIVE_NAME_OUTPUT_CAP {
        let value = std::str::from_utf8(&output.stdout).ok()?;
        if let Some(value) = normalize_host_display_name(value) {
            return Some(value);
        }
    }
    hostname_file(Path::new("/etc/hostname"))
}

#[cfg(target_os = "linux")]
fn platform_display_name() -> Option<String> {
    parse_assignment_file(Path::new("/etc/machine-info"), "PRETTY_HOSTNAME")
        .and_then(|value| normalize_host_display_name(&value))
        .or_else(|| hostname_file(Path::new("/etc/hostname")))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_display_name() -> Option<String> {
    None
}

fn hostname_file(path: &Path) -> Option<String> {
    let value = read_bounded_text(path)?;
    normalize_host_display_name(value.lines().next()?)
}

#[cfg(target_os = "linux")]
fn linux_distribution() -> (Option<String>, Option<String>) {
    let id = parse_assignment_file(Path::new("/etc/os-release"), "ID")
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| valid_host_metadata_token(value));
    let version = parse_assignment_file(Path::new("/etc/os-release"), "VERSION_ID")
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| valid_host_metadata_token(value));
    (id, version)
}

#[cfg(any(target_os = "linux", test))]
fn parse_assignment_file(path: &Path, key: &str) -> Option<String> {
    let text = read_bounded_text(path)?;
    for line in text.lines() {
        let Some((candidate, raw)) = line.split_once('=') else {
            continue;
        };
        if candidate != key {
            continue;
        }
        let value = unquote_simple(raw)?;
        if value.len() > NATIVE_NAME_OUTPUT_CAP {
            return None;
        }
        return Some(value.to_owned());
    }
    None
}

#[cfg(any(target_os = "linux", test))]
fn unquote_simple(value: &str) -> Option<&str> {
    if let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        // Do not interpret file escape syntax. A value that needs decoding is skipped rather than
        // allowing arbitrary file syntax to cross the protocol boundary.
        return (!inner.contains('\\')).then_some(inner);
    }
    if let Some(inner) = value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
        return Some(inner);
    }
    (!value.contains(['"', '\'', '\\'])).then_some(value)
}

fn read_bounded_text(path: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > LOCAL_METADATA_FILE_CAP
    {
        return None;
    }
    let file = File::open(path).ok()?;
    let mut reader: Take<File> = file.take(LOCAL_METADATA_FILE_CAP + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > LOCAL_METADATA_FILE_CAP {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn parses_only_bounded_simple_assignments() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("metadata");
        fs::write(
            &path,
            "ID=Debian\nVERSION_ID=\"13\"\nPRETTY_HOSTNAME='Alpha Host'\n",
        )
        .unwrap();
        assert_eq!(
            parse_assignment_file(&path, "ID").as_deref(),
            Some("Debian")
        );
        assert_eq!(
            parse_assignment_file(&path, "VERSION_ID").as_deref(),
            Some("13")
        );
        assert_eq!(
            parse_assignment_file(&path, "PRETTY_HOSTNAME").as_deref(),
            Some("Alpha Host")
        );

        fs::write(&path, "PRETTY_HOSTNAME=\"escaped\\nname\"\n").unwrap();
        assert!(parse_assignment_file(&path, "PRETTY_HOSTNAME").is_none());
    }

    #[test]
    fn metadata_reader_rejects_links_and_oversize() {
        let temp = tempdir().unwrap();
        let real = temp.path().join("real");
        let link = temp.path().join("link");
        fs::write(&real, "safe").unwrap();
        symlink(&real, &link).unwrap();
        assert!(read_bounded_text(&link).is_none());

        fs::write(&real, vec![b'a'; LOCAL_METADATA_FILE_CAP as usize + 1]).unwrap();
        assert!(read_bounded_text(&real).is_none());
    }

    #[test]
    fn machine_token_is_a_stable_truncated_hash_never_the_raw_id() {
        let raw = "0123456789abcdef0123456789abcdef";
        let token = derive_machine_token(raw);
        assert_eq!(token, derive_machine_token(raw));
        assert_eq!(token.len(), 32);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_ne!(token, raw);
        assert_ne!(derive_machine_token("another-machine"), token);
    }

    #[test]
    fn machine_id_file_requires_exactly_32_hex() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("machine-id");
        fs::write(&path, "8DE20B67C2AA429A8F103E7DA6E7D3C1\n").unwrap();
        assert_eq!(
            machine_id_file(&path).as_deref(),
            Some("8de20b67c2aa429a8f103e7da6e7d3c1")
        );
        fs::write(&path, "not-a-machine-id\n").unwrap();
        assert!(machine_id_file(&path).is_none());
    }

    #[test]
    fn architecture_is_one_of_the_distribution_targets() {
        assert!(matches!(
            normalized_architecture().as_deref(),
            Ok("aarch64" | "x86_64")
        ));
    }
}
