//! Private-copy Codex image proof. Only the hidden, single-threaded helper calls blocking APIs.
//! A cdhash binds code, not a publisher or uninterrupted execution. Same-user malicious mutation
//! is outside the boundary: 0700/0500 custody protects against ordinary updater replacement.

mod digest;
mod security;
mod snapshot;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const HELPER_ARGUMENT: &str = "--ciao-native-codex-image-v1";
pub const MAX_PROTOCOL: usize = 8192;
pub use crate::{MAX_PROBE_IMAGE_BYTES as MAX_IMAGE, PROBE_ALARM_SECONDS as HELPER_SECONDS};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CodeHash(String);
impl<'de> Deserialize<'de> for CodeHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| serde::de::Error::custom("invalid code hash"))
    }
}
impl CodeHash {
    pub fn parse(text: &str) -> Option<Self> {
        (text.len() == 40
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .then(|| Self(text.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Architecture {
    Arm64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub pid: u32,
    pub identity: String,
}
impl Backend {
    fn valid(&self) -> bool {
        self.pid > 0
            && self.identity.len() <= 64
            && crate::native_identity(self.pid).as_deref() == Some(&self.identity)
            && security::native_arm64(self.pid)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub root: PathBuf,
    pub nonce: String,
    pub owner: Backend,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub transaction: Transaction,
    pub backend: Backend,
    pub architecture: Architecture,
    pub code_hash: CodeHash,
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum Request {
    Prepare {
        transaction: Transaction,
        backend: Backend,
    },
    Execute {
        snapshot: Snapshot,
    },
    Finish {
        snapshot: Snapshot,
    },
    Revalidate {
        backend: Backend,
        code_hash: CodeHash,
    },
    Cleanup {
        transaction: Transaction,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", deny_unknown_fields)]
pub enum Reply {
    Prepared { snapshot: Snapshot },
    Valid {},
    Clean {},
}

/// Dispatch before Tokio/tracing initialization. Never reports vendor bytes, paths or API errors.
/// Malformed hidden invocations terminate rather than falling through to ordinary CLI parsing.
pub fn helper_entry() -> Option<i32> {
    let mut args = std::env::args_os();
    args.next();
    if args.next().as_deref() != Some(std::ffi::OsStr::new(HELPER_ARGUMENT)) {
        return None;
    }
    if crate::prepare_probe_helper(HELPER_SECONDS).is_none() {
        return Some(1);
    }
    let result = (|| {
        let text = args.next()?;
        let text = text.to_str()?;
        if text.len() > MAX_PROTOCOL || args.next().is_some() {
            return None;
        }
        let request: Request = serde_json::from_str(text).ok()?;
        let reply = match request {
            Request::Prepare {
                transaction,
                backend,
            } => Reply::Prepared {
                snapshot: snapshot::prepare(transaction, backend)?,
            },
            Request::Execute { snapshot } => {
                snapshot::execute(&snapshot)?;
                return None;
            }
            Request::Finish { snapshot } => {
                snapshot::finish(&snapshot)?;
                Reply::Valid {}
            }
            Request::Revalidate { backend, code_hash } => {
                dynamic(&backend, &code_hash)?;
                Reply::Valid {}
            }
            Request::Cleanup { transaction } => {
                snapshot::cleanup(&transaction)?;
                Reply::Clean {}
            }
        };
        let bytes = serde_json::to_vec(&reply).ok()?;
        if bytes.len() > MAX_PROTOCOL {
            return None;
        }
        use std::io::Write;
        std::io::stdout().write_all(&bytes).ok()?;
        Some(())
    })();
    Some(if result.is_some() { 0 } else { 1 })
}

fn dynamic(backend: &Backend, hash: &CodeHash) -> Option<()> {
    if CodeHash::parse(hash.as_str()).as_ref() != Some(hash) || !backend.valid() {
        return None;
    }
    security::dynamic(backend.pid, hash)?;
    backend.valid().then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash_grammar_and_protocol_refuse_ambiguity() {
        assert!(CodeHash::parse(&"a".repeat(40)).is_some());
        for s in [
            "A".repeat(40),
            "0".repeat(39),
            "0".repeat(41),
            "g".repeat(40),
            "\"".repeat(40),
        ] {
            assert!(CodeHash::parse(&s).is_none());
            assert!(serde_json::from_value::<CodeHash>(serde_json::json!(s)).is_err());
        }
        for s in [
            r#"{"result":"Valid","extra":1}"#,
            r#"{"result":"Clean","extra":1}"#,
        ] {
            assert!(serde_json::from_str::<Reply>(s).is_err());
        }
        for s in [
            r#"{"operation":"Revalidate","operation":"Cleanup"}"#,
            r#"{"operation":"Cleanup","transaction":{},"extra":1}"#,
        ] {
            assert!(serde_json::from_str::<Request>(s).is_err());
        }
    }
}
