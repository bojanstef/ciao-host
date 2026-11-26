//! Destination-only policy for Claude's headless Code Mode. A resume follows its
//! transcript, while a new conversation follows the owner's user settings.
use std::{
    env,
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
};

use serde::Deserialize;
use serde_json::Value;
use tokio_tungstenite::tungstenite::http::Uri;

const FLAG: &str = "CLAUDE_CODE_EXPERIMENTAL_CODE_MODE";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Conversation {
    New,
    Plain,
    CodeMode,
}

impl Conversation {
    pub(crate) fn from_resume(id: Option<&str>) -> Self {
        match id {
            None => Self::New,
            Some(id) if crate::claude_transcript::code_mode(id) => Self::CodeMode,
            Some(_) => Self::Plain,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LaunchMode {
    Default,
    Enable,
    TerminalOnly,
}

/// Ignore unrelated settings (including the global conversation index). An existing file
/// that cannot be checked is distinct from an absent opt-out.
#[derive(Default, Deserialize)]
struct Settings {
    #[serde(default)]
    env: Value,
}

fn read_json<T: serde::de::DeserializeOwned + Default>(path: &Path) -> io::Result<T> {
    let metadata = match path.metadata() {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(T::default()),
        other => other?,
    };
    if !metadata.is_file() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // Global settings grow with the user's project history. Deserialize only the needed
    // fields, streaming the original file length so a concurrent append cannot extend the read.
    let file = File::open(path)?;
    let limit = file.metadata()?.len();
    Ok(serde_json::from_reader(BufReader::new(file.take(limit)))?)
}

fn config_env(doc: &Value, key: &str) -> Option<String> {
    let vars = doc.as_object()?;
    let value = vars.get(key).or_else(|| {
        vars.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    })?;
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Bool(_) | Value::Number(_) => Some(value.to_string()),
        _ => None,
    }
}

fn on(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "on" | "yes"
    )
}

fn decide(
    conversation: Conversation,
    version: &str,
    user: &Value,
    global: &Value,
    environment: impl Fn(&str) -> Option<String>,
) -> LaunchMode {
    let user_flag = config_env(user, FLAG);
    let required = conversation == Conversation::CodeMode;
    if !required && (conversation == Conversation::Plain || !user_flag.as_deref().is_some_and(on)) {
        return LaunchMode::Default;
    }
    // An explicit opt-out at any of these three sources wins over --settings.
    let veto = [environment(FLAG), user_flag, config_env(global, FLAG)]
        .iter()
        .flatten()
        .any(|v| !on(v));
    if veto {
        return if required {
            LaunchMode::TerminalOnly
        } else {
            LaunchMode::Default
        };
    }
    let effective = |key: &str| {
        config_env(user, key)
            .or_else(|| config_env(global, key))
            .or_else(|| environment(key))
    };
    let cloud = [
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        "CLAUDE_CODE_USE_ANTHROPIC_AWS",
        "CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD",
        "CLAUDE_CODE_USE_MANTLE",
    ]
    .iter()
    .any(|key| effective(key).as_deref().is_some_and(on));
    let gateway = effective("ANTHROPIC_BASE_URL").is_some_and(|url| {
        !url.is_empty()
            && !url.parse::<Uri>().ok().is_some_and(|uri| {
                uri.host()
                    .is_some_and(|host| host.eq_ignore_ascii_case("api.anthropic.com"))
                    && uri.port_u16().is_none_or(|port| port == 443)
            })
    });
    let unavailable = crate::agent_protocol::parse_version(version) < Some((2, 1, 330))
        || cloud
        || gateway
        || effective("ANTHROPIC_UNIX_SOCKET").is_some()
        || effective("CLAUDE_AGENT_SDK_MCP_NO_PREFIX").is_some_and(|s| !s.is_empty());
    if unavailable {
        LaunchMode::TerminalOnly
    } else {
        LaunchMode::Enable
    }
}

pub(crate) fn launch_mode(conversation: Conversation, version: &str) -> LaunchMode {
    if conversation == Conversation::Plain {
        return LaunchMode::Default;
    }
    let config = crate::claude_transcript::claude_config_dir();
    let global_dir = if env::var_os("CLAUDE_CONFIG_DIR").is_some_and(|v| !v.is_empty()) {
        config.clone()
    } else {
        env::var_os("HOME").map(Into::into)
    };
    mode_in(
        conversation,
        version,
        config.as_deref(),
        global_dir.as_deref(),
        |key| env::var(key).ok(),
    )
}

fn mode_in(
    conversation: Conversation,
    version: &str,
    config: Option<&Path>,
    global_dir: Option<&Path>,
    environment: impl Fn(&str) -> Option<String>,
) -> LaunchMode {
    let user = config
        .map(|dir| read_json::<Settings>(&dir.join("settings.json")))
        .transpose();
    let global = global_dir
        .map(|dir| read_json::<Settings>(&dir.join(".claude.json")))
        .transpose();
    match (user, global) {
        (Ok(user), Ok(global)) => decide(
            conversation,
            version,
            &user.unwrap_or_default().env,
            &global.unwrap_or_default().env,
            environment,
        ),
        _ if conversation == Conversation::CodeMode => LaunchMode::TerminalOnly,
        _ => LaunchMode::Default,
    }
}

/// Preflight uses the installed manifest. Launch still verifies the exact pair and binary digest.
pub(crate) fn terminal_only(prefix: &Path) -> bool {
    #[derive(Deserialize, Default)]
    struct Manifest {
        version: String,
    }
    if !crate::managed_worker::native_cli(prefix)
        .is_some_and(|(_, path)| crate::pty::is_absolute_executable(&path))
    {
        return true;
    }
    let manifest = read_json::<Manifest>(
        &prefix.join("node_modules/@anthropic-ai/claude-agent-sdk/manifest.json"),
    )
    .ok();
    let version = manifest
        .as_ref()
        .map(|m| m.version.as_str())
        .unwrap_or_default();
    launch_mode(Conversation::CodeMode, version) == LaunchMode::TerminalOnly
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_compatible_manifest_without_its_native_cli_cannot_take_over() {
        let root = tempfile::tempdir().unwrap();
        let wrapper = root
            .path()
            .join("node_modules/@anthropic-ai/claude-agent-sdk");
        std::fs::create_dir_all(&wrapper).unwrap();
        std::fs::write(wrapper.join("manifest.json"), r#"{"version":"2.1.332"}"#).unwrap();
        assert!(terminal_only(root.path()));
    }

    #[test]
    fn new_and_resumed_chats_read_the_destination_files() {
        let root = tempfile::tempdir().unwrap();
        let user = root.path().join(".claude");
        std::fs::create_dir(&user).unwrap();
        let mode = |chat| mode_in(chat, "2.1.332", Some(&user), Some(root.path()), |_| None);
        assert_eq!(mode(Conversation::New), LaunchMode::Default);
        assert_eq!(mode(Conversation::CodeMode), LaunchMode::Enable);
        std::fs::write(
            user.join("settings.json"),
            json!({"env":{FLAG:"1"}}).to_string(),
        )
        .unwrap();
        assert_eq!(mode(Conversation::New), LaunchMode::Enable);
        assert_eq!(mode(Conversation::Plain), LaunchMode::Default);
        std::fs::write(
            root.path().join(".claude.json"),
            json!({"env":{FLAG:"false"}}).to_string(),
        )
        .unwrap();
        assert_eq!(mode(Conversation::CodeMode), LaunchMode::TerminalOnly);
        assert_eq!(mode(Conversation::New), LaunchMode::Default);
    }

    #[test]
    fn headless_code_mode_follows_the_conversation_and_destination() {
        let empty = &Value::Null;
        let enabled = &json!({FLAG: " YES "});
        let disabled = &json!({FLAG: "Off"});
        fn mode(
            chat: Conversation,
            version: &str,
            user: &Value,
            global: &Value,
            process: &Value,
        ) -> LaunchMode {
            decide(chat, version, user, global, |key| config_env(process, key))
        }
        use Conversation::{CodeMode, New, Plain};
        use LaunchMode::{Default, Enable, TerminalOnly};
        let pin = crate::claude_managed_adapter::PINNED_MANAGED_CLI_VERSION;
        assert_eq!(mode(New, pin, empty, enabled, enabled), Default);
        assert_eq!(mode(Plain, pin, enabled, empty, empty), Default);
        assert_eq!(mode(New, pin, enabled, empty, empty), Enable);
        assert_eq!(mode(CodeMode, "2.1.330", empty, empty, empty), Enable);
        assert_eq!(
            mode(CodeMode, "2.1.329", enabled, empty, empty),
            TerminalOnly
        );
        for (user, global, shell) in [
            (disabled, enabled, empty),
            (enabled, disabled, empty),
            (enabled, empty, disabled),
        ] {
            assert_eq!(mode(CodeMode, pin, user, global, shell), TerminalOnly);
            assert_eq!(mode(New, pin, user, global, shell), Default);
        }
        for (key, value) in [
            ("CLAUDE_CODE_USE_BEDROCK", "1"),
            ("CLAUDE_CODE_USE_VERTEX", "true"),
            ("CLAUDE_CODE_USE_FOUNDRY", "on"),
            ("ANTHROPIC_BASE_URL", "https://gateway.invalid"),
            ("CLAUDE_AGENT_SDK_MCP_NO_PREFIX", "1"),
            ("ANTHROPIC_UNIX_SOCKET", "/socket"),
            ("CLAUDE_CODE_USE_ANTHROPIC_AWS", "1"),
            ("CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD", "1"),
            ("CLAUDE_CODE_USE_MANTLE", "1"),
        ] {
            assert_eq!(
                mode(CodeMode, pin, empty, empty, &json!({key:value})),
                TerminalOnly,
                "{key}"
            );
            assert_eq!(
                mode(New, pin, enabled, &json!({key:value}), empty),
                TerminalOnly,
                "{key}"
            );
        }
        assert_eq!(
            mode(
                CodeMode,
                pin,
                &json!({"ANTHROPIC_BASE_URL":"https://api.anthropic.com/"}),
                empty,
                empty
            ),
            Enable
        );
    }
}
