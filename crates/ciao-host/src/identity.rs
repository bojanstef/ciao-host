use std::{
    fs, io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{EndpointId, SecretKey};
use serde::{Deserialize, Serialize};

use crate::storage::{
    CiaoPaths, atomic_write_private, validate_endpoint_id, validate_private_file,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialsFile {
    v: u8,
    /// The 32 raw Iroh secret-key bytes, encoded as RFC 4648 base64url without padding.
    secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub v: u8,
    pub host_endpoint_id: String,
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub struct HostIdentity {
    pub secret_key: SecretKey,
    pub endpoint_id: EndpointId,
    pub config: HostConfig,
}

#[derive(Debug)]
pub struct IdentitySetup {
    pub identity: HostIdentity,
    pub created: bool,
    pub repaired_config: bool,
}

pub fn load_identity(paths: &CiaoPaths) -> Result<Option<HostIdentity>> {
    let credentials_exist = path_entry_exists(&paths.credentials_file)?;
    let config_exists = path_entry_exists(&paths.config_file)?;
    match (credentials_exist, config_exists) {
        (false, false) => Ok(None),
        (false, true) => bail!(
            "host configuration exists but {} is missing; restore the credential file or reset Ciao explicitly",
            paths.credentials_file.display()
        ),
        (true, false) => bail!(
            "host credentials exist but {} is missing; run `ciao setup --yes` to repair configuration without rotating the identity",
            paths.config_file.display()
        ),
        (true, true) => load_complete_identity(paths).map(Some),
    }
}

pub fn create_or_load_identity(paths: &CiaoPaths) -> Result<IdentitySetup> {
    paths.ensure_layout()?;
    let credentials_exist = path_entry_exists(&paths.credentials_file)?;
    let config_exists = path_entry_exists(&paths.config_file)?;
    match (credentials_exist, config_exists) {
        (false, false) => create_identity(paths),
        (false, true) => bail!(
            "host configuration exists but {} is missing; refusing to rotate the configured identity. Restore it or use the documented reset procedure",
            paths.credentials_file.display()
        ),
        (true, false) => {
            let secret_key = read_secret_key(&paths.credentials_file)?;
            let endpoint_id = secret_key.public();
            let config = HostConfig {
                v: 1,
                host_endpoint_id: endpoint_id.to_string(),
                created_at: unix_now()?,
            };
            write_json_private(&paths.config_file, &config)?;
            Ok(IdentitySetup {
                identity: HostIdentity {
                    secret_key,
                    endpoint_id,
                    config,
                },
                created: false,
                repaired_config: true,
            })
        }
        (true, true) => Ok(IdentitySetup {
            identity: load_complete_identity(paths)?,
            created: false,
            repaired_config: false,
        }),
    }
}

fn create_identity(paths: &CiaoPaths) -> Result<IdentitySetup> {
    let secret_key = SecretKey::generate();
    let endpoint_id = secret_key.public();
    let credentials = CredentialsFile {
        v: 1,
        secret_key: URL_SAFE_NO_PAD.encode(secret_key.to_bytes()),
    };
    // Credentials are committed first. If setup is interrupted, the config can be repaired from
    // this key; the reverse order could leave a configured host with no identity.
    write_json_private(&paths.credentials_file, &credentials)?;
    let config = HostConfig {
        v: 1,
        host_endpoint_id: endpoint_id.to_string(),
        created_at: unix_now()?,
    };
    if let Err(error) = write_json_private(&paths.config_file, &config) {
        return Err(error).context(
            "host key was created safely, but config creation failed; rerun `ciao setup --yes` to repair it",
        );
    }
    Ok(IdentitySetup {
        identity: HostIdentity {
            secret_key,
            endpoint_id,
            config,
        },
        created: true,
        repaired_config: false,
    })
}

fn load_complete_identity(paths: &CiaoPaths) -> Result<HostIdentity> {
    let secret_key = read_secret_key(&paths.credentials_file)?;
    let endpoint_id = secret_key.public();
    validate_private_file(&paths.config_file)?;
    let bytes = fs::read(&paths.config_file)
        .with_context(|| format!("read {}", paths.config_file.display()))?;
    let config: HostConfig = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "{} is malformed; refusing to rotate the host identity",
            paths.config_file.display()
        )
    })?;
    if config.v != 1 {
        bail!("unsupported host config version {}", config.v);
    }
    validate_endpoint_id(&config.host_endpoint_id)?;
    if config.host_endpoint_id != endpoint_id.to_string() {
        bail!(
            "cached host endpoint ID does not match the credential key; restore matching files or reset Ciao explicitly"
        );
    }
    Ok(HostIdentity {
        secret_key,
        endpoint_id,
        config,
    })
}

fn read_secret_key(path: &Path) -> Result<SecretKey> {
    validate_private_file(path)?;
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let credentials: CredentialsFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is malformed; refusing to rotate it", path.display()))?;
    if credentials.v != 1 {
        bail!("unsupported credentials version {}", credentials.v);
    }
    if credentials.secret_key.contains('=') {
        bail!("credential key must use base64url without padding");
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(credentials.secret_key)
        .context("credential key is not valid base64url")?;
    let key_bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("credential key must decode to exactly 32 bytes"))?;
    Ok(SecretKey::from_bytes(&key_bytes))
}

fn write_json_private(path: &Path, value: &impl Serialize) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(value)?;
    atomic_write_private(path, &encoded)
}

fn path_entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
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
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn identity_persists_with_private_permissions() {
        let temp = tempdir().unwrap();
        let paths = CiaoPaths::for_home(temp.path());
        let first = create_or_load_identity(&paths).unwrap();
        assert!(first.created);
        let second = load_identity(&paths).unwrap().unwrap();
        assert_eq!(first.identity.endpoint_id, second.endpoint_id);
        assert_eq!(
            first.identity.secret_key.to_bytes(),
            second.secret_key.to_bytes()
        );
        assert_eq!(
            fs::metadata(paths.credentials_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(paths.config_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn malformed_identity_is_never_rotated() {
        let temp = tempdir().unwrap();
        let paths = CiaoPaths::for_home(temp.path());
        paths.ensure_layout().unwrap();
        atomic_write_private(&paths.credentials_file, br#"{"v":1,"secret_key":"bad"}"#).unwrap();
        atomic_write_private(
            &paths.config_file,
            br#"{"v":1,"host_endpoint_id":"bad","created_at":1}"#,
        )
        .unwrap();
        assert!(create_or_load_identity(&paths).is_err());
        assert_eq!(
            fs::read_to_string(paths.credentials_file).unwrap(),
            r#"{"v":1,"secret_key":"bad"}"#
        );
    }

    #[test]
    fn credential_only_interruption_repairs_without_rotation() {
        let temp = tempdir().unwrap();
        let paths = CiaoPaths::for_home(temp.path());
        paths.ensure_layout().unwrap();
        let key = SecretKey::generate();
        write_json_private(
            &paths.credentials_file,
            &CredentialsFile {
                v: 1,
                secret_key: URL_SAFE_NO_PAD.encode(key.to_bytes()),
            },
        )
        .unwrap();
        let setup = create_or_load_identity(&paths).unwrap();
        assert!(setup.repaired_config);
        assert_eq!(setup.identity.endpoint_id, key.public());
    }
}
