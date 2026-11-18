//! Typed one-shot requests for the paired phone's Herdr controls.
use super::{
    HOST_PROTOCOL_VERSION, HostProtocolError, valid_herdr_core_tab_id, valid_machine_token,
    valid_session_name, valid_tab_id, valid_tab_label, validate_request_id,
};
use serde::Deserialize;
use serde_json::Value;

pub const SPACES: &str = "herdr.core.spaces.v1";
pub const CREATE: &str = "herdr.core.create.v1";
pub const SPACE_ACTION: &str = "herdr.core.space.action.v1";
pub const DESKTOP_TAB_ACTION: &str = "herdr.core.tab.action.v1";
pub const TUI_INSPECT: &str = "herdr.tui.tab.inspect.v1";
pub const TAB_ACTION: &str = "herdr.tab.action.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: String,
    pub operation: Operation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Catalog,
    Inspect(TuiInspection),
    Create(CreateParams),
    Space(SpaceParams),
    Tab(TabParams),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreateParams {
    pub session: String,
    pub core: String,
    pub destination: Destination,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Destination {
    NewSpace { name: String },
    ExistingSpace { space: String },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpaceParams {
    pub session: String,
    pub core: String,
    pub space: String,
    pub tab: Option<String>,
    pub version: u64,
    pub action: Action,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TuiInspection {
    pub session: String,
    pub tab: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TabParams {
    pub session: String,
    pub tab: String,
    pub target: TabTarget,
    pub instance: Option<String>,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum TabTarget {
    #[serde(rename = "herdr_core.attach")]
    Core,
    #[serde(rename = "herdr.attach")]
    Tui,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Close {},
    Rename { name: String },
}

impl Action {
    fn valid(&self) -> bool {
        match self {
            Self::Close {} => true,
            Self::Rename { name } => valid_name(name),
        }
    }
}

fn valid_name(name: &str) -> bool {
    name == name.trim() && valid_tab_label(name)
}

pub(crate) fn valid_space_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn canonical_tui_tab(value: &str) -> bool {
    // Upstream also accepts positional aliases (e.g. 1:2). Never mutate through one.
    valid_tab_id(value)
        && value
            .split_once(":t")
            .is_some_and(|(w, t)| w.strip_prefix('w').is_some_and(counter) && counter(t))
}
fn counter(digits: &str) -> bool {
    !digits.is_empty()
        && digits
            .bytes()
            .all(|c| b"123456789ABCDEFGHJKMNPQRSTVWXYZ0".contains(&c))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    v: u8,
    #[serde(rename = "type")]
    ty: String,
    request_id: String,
    method: String,
    params: Value,
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Request, HostProtocolError> {
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|_| HostProtocolError::MalformedJson)?;
    validate_request_id(&envelope.request_id)?;
    if envelope.v != HOST_PROTOCOL_VERSION || envelope.ty != "request" {
        return Err(HostProtocolError::InvalidControlValue);
    }
    let invalid = |_| HostProtocolError::InvalidControlValue;
    let params = envelope.params;
    let operation = match envelope.method.as_str() {
        SPACES if params.as_object().is_some_and(|p| p.is_empty()) => Operation::Catalog,
        CREATE => {
            let p: CreateParams = serde_json::from_value(params).map_err(invalid)?;
            if !valid_session_name(&p.session)
                || !valid_machine_token(&p.core)
                || !match &p.destination {
                    Destination::ExistingSpace { space } => valid_space_id(space),
                    Destination::NewSpace { name } => valid_name(name),
                }
            {
                return Err(HostProtocolError::InvalidTarget);
            }
            Operation::Create(p)
        }
        SPACE_ACTION | DESKTOP_TAB_ACTION => {
            let is_tab = envelope.method == DESKTOP_TAB_ACTION;
            if is_tab != params.get("tab").is_some() {
                return Err(HostProtocolError::InvalidTarget);
            }
            let p: SpaceParams = serde_json::from_value(params).map_err(invalid)?;
            if !valid_session_name(&p.session)
                || !valid_machine_token(&p.core)
                || (is_tab && !p.tab.as_deref().is_some_and(valid_space_id))
                || !valid_space_id(&p.space)
                || !p.action.valid()
            {
                return Err(HostProtocolError::InvalidTarget);
            }
            Operation::Space(p)
        }
        TUI_INSPECT => {
            let p: TuiInspection = serde_json::from_value(params).map_err(invalid)?;
            if !valid_session_name(&p.session) || !canonical_tui_tab(&p.tab) {
                return Err(HostProtocolError::InvalidTarget);
            }
            Operation::Inspect(p)
        }
        TAB_ACTION => {
            let p: TabParams = serde_json::from_value(params).map_err(invalid)?;
            if !valid_session_name(&p.session)
                || !p.action.valid()
                || !match p.target {
                    TabTarget::Core => {
                        valid_herdr_core_tab_id(&p.tab)
                            && p.instance.is_none()
                            && matches!(p.action, Action::Close {})
                    }
                    TabTarget::Tui => {
                        canonical_tui_tab(&p.tab)
                            && p.instance.as_deref().is_some_and(valid_machine_token)
                    }
                }
            {
                return Err(HostProtocolError::InvalidTarget);
            }
            Operation::Tab(p)
        }
        _ => return Err(HostProtocolError::InvalidControlValue),
    };
    Ok(Request {
        id: envelope.request_id,
        operation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_protocol::{RpcRequest, decode_rpc_request};
    use serde_json::json;

    #[test]
    fn shared_requests_and_strict_targets() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../protocol/fixtures/phase9/herdr-management-v1.json"
        ))
        .unwrap();
        for (key, case) in fixture["cases"].as_object().unwrap() {
            let req = &case["request"];
            assert!(
                matches!(
                    decode_rpc_request(&serde_json::to_vec(req).unwrap()),
                    Ok(RpcRequest::HerdrManagement(_))
                ),
                "{key}"
            );
            assert_eq!(case["response"]["request_id"], req["request_id"]);
            let mut unknown = req.clone();
            unknown["params"]["path"] = json!("/tmp");
            assert!(decode_rpc_request(&serde_json::to_vec(&unknown).unwrap()).is_err());
        }
        for (key, field, value) in [
            ("close_terminal", "instance", json!("a".repeat(32))),
            ("close_tui", "instance", Value::Null),
            ("close_tui", "tab", json!("w1:1")),
            ("close_tui", "tab", json!("w_1:t2")),
            ("close_space", "space", json!("other/sp1")),
            (
                "new_space",
                "destination",
                json!({"kind":"new_space","name":" "}),
            ),
            (
                "close_terminal",
                "action",
                json!({"kind":"close","name":"unused"}),
            ),
        ] {
            let mut req = fixture["cases"][key]["request"].clone();
            req["params"][field] = value;
            assert!(
                decode_rpc_request(&serde_json::to_vec(&req).unwrap()).is_err(),
                "{key}/{field}"
            );
        }
    }
}
