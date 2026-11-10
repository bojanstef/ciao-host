//! Explicit creation, never an attach retry or a command typed into a user's terminal.
use serde_json::Value;

use crate::{
    host_protocol::{
        CreatedTerminalTab as CreatedTab, ProviderKind, TerminalTabCreateParams as CreateParams,
        valid_tab_id,
    },
    workspace::{WorkspaceConfig, run_bounded},
};

pub(crate) async fn create(config: &WorkspaceConfig, params: &CreateParams) -> Option<CreatedTab> {
    params.validate().ok()?;
    let tab = if let Some(binding) = &params.tab {
        crate::herdr_core::create_terminal(&config.core, &params.session, binding)
            .await
            .ok()?
    } else {
        let binary = config.resolve(ProviderKind::Herdr)?;
        // API commands connect to an existing server; unlike `herdr --session NAME` alone,
        // they never launch one. Focus/cwd/shell policy belongs to Herdr, not Ciao.
        let output = run_bounded(
            &binary,
            &["--session", &params.session, "tab", "create", "--focus"],
        )
        .await
        .ok()?;
        if !output.status_success {
            return None;
        }
        parse_created_tab(&output.stdout)?
    };
    Some(CreatedTab { tab })
}

fn parse_created_tab(bytes: &[u8]) -> Option<String> {
    if bytes.len() > 64 * 1024 {
        return None;
    }
    let value: Value = serde_json::from_slice(bytes).ok()?;
    fn bounded(value: &Value, left: usize) -> bool {
        left > 0
            && match value {
                Value::Array(items) => items.iter().all(|v| bounded(v, left - 1)),
                Value::Object(items) => items.values().all(|v| bounded(v, left - 1)),
                _ => true,
            }
    }
    if !bounded(&value, 12) || value.get("error").is_some() {
        return None;
    }
    let result = value.get("result")?.as_object()?;
    for key in result
        .keys()
        .filter(|k| !["type", "tab", "root_pane"].contains(&k.as_str()))
    {
        crate::drift::note("herdr", "tab_create", "unknown_field", key, None);
    }
    if result.get("type")?.as_str()? != "tab_created" {
        return None;
    }
    let tab = result.get("tab")?.as_object()?;
    for key in tab.keys().filter(|k| {
        ![
            "tab_id",
            "workspace_id",
            "number",
            "label",
            "focused",
            "pane_count",
            "agent_status",
        ]
        .contains(&k.as_str())
    }) {
        crate::drift::note("herdr", "tab_create_tab", "unknown_field", key, None);
    }
    tab.get("tab_id")?
        .as_str()
        .filter(|id| valid_tab_id(id))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_protocol::TerminalTabCreateRequest as CreateRequest;
    use serde_json::json;

    #[test]
    fn shared_contract_and_hostile_requests() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../protocol/fixtures/phase9/terminal-tab-create-v1.json"
        ))
        .unwrap();
        for provider in ["tui", "core"] {
            let request: CreateRequest =
                serde_json::from_value(fixture[format!("{provider}_request")].clone()).unwrap();
            request.validate().unwrap();
            assert!(matches!(
                crate::host_protocol::decode_rpc_request(&serde_json::to_vec(&request).unwrap())
                    .unwrap(),
                crate::host_protocol::RpcRequest::TerminalTabCreate(_)
            ));
            let expected = &fixture[format!("{provider}_response")];
            let response = crate::host_protocol::TerminalTabCreateResponse {
                v: 1,
                message_type: "response",
                request_id: request.request_id,
                result: CreatedTab {
                    tab: expected["result"]["tab"].as_str().unwrap().into(),
                },
            };
            assert_eq!(serde_json::to_value(response).unwrap(), *expected);
        }
        for params in fixture["invalid_params"].as_array().unwrap() {
            if let Ok(params) = serde_json::from_value::<CreateParams>(params.clone()) {
                assert!(params.validate().is_err());
            }
        }
    }

    #[test]
    fn tui_creation_requires_success_shape_and_safe_identity() {
        let good = json!({"result":{"type":"tab_created","tab":{"tab_id":"w1:t2"},"root_pane":{}}});
        assert_eq!(
            parse_created_tab(&serde_json::to_vec(&good).unwrap()).as_deref(),
            Some("w1:t2")
        );
        for bad in [
            json!({"error":{},"result":good["result"]}),
            json!({"result":{"type":"tab_created","tab":{"tab_id":"--bad"}}}),
            json!({"result":{"type":"tab_info","tab":{"tab_id":"w1:t2"}}}),
        ] {
            assert!(parse_created_tab(&serde_json::to_vec(&bad).unwrap()).is_none());
        }
        assert!(parse_created_tab(&vec![b' '; 65537]).is_none());
    }
}
