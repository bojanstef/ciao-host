//! Desktop's machine-owned layout lives in the local Core's versioned `herdr-app` document.
mod tui;

use super::{
    CoreConfig, CoreError, DISCOVERY_BUDGET, QUERY_TIMEOUT, note, parse_hello,
    plain_call as core_call,
};
use crate::{
    host_protocol::{
        MAX_RPC_BODY, MAX_TABS_PER_SESSION,
        herdr_management::{
            Action, CreateParams, Destination, Operation, SpaceParams, TabParams, TabTarget,
            valid_space_id,
        },
        valid_herdr_core_tab_id,
    },
    workspace::{WorkspaceConfig, sanitize_tab_label},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
    time::Duration,
};
use tokio::{io::BufReader, net::UnixStream, time::timeout};

type Stream = BufReader<UnixStream>;
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(5);

// Core's terminal.kill can take three seconds while it escalates signals. Bound
// each provider exchange independently so one stalled server cannot occupy the close slot.
async fn plain_call(
    stream: &mut Stream,
    id: u32,
    method: &str,
    params: Value,
) -> Result<Value, CoreError> {
    timeout(PROVIDER_TIMEOUT, core_call(stream, id, method, params))
        .await
        .map_err(|_| CoreError::Unavailable)?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    Unavailable,
    Changed,
    Busy,
    ConfirmationRequired,
    Unconfirmed,
}

impl Failure {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Unavailable => "herdr_unavailable",
            Self::Changed => "herdr_target_changed",
            Self::ConfirmationRequired => "herdr_confirmation_required",
            Self::Unconfirmed => "herdr_unconfirmed",
        }
    }
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Busy => "A Herdr close is already running.",
            Self::Unavailable => "Could not read this host’s Herdr layout.",
            Self::Changed => "The Herdr target changed. Refresh and select it again.",
            Self::ConfirmationRequired => "Herdr requires confirmation in its TUI.",
            Self::Unconfirmed => {
                "Check the host’s spaces and terminals before trying again. The change may have taken effect."
            }
        }
    }
}

impl From<CoreError> for Failure {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::Conflict | CoreError::TerminalMissing => Self::Changed,
            _ => Self::Unavailable,
        }
    }
}

pub(crate) async fn execute(
    config: &WorkspaceConfig,
    operation: Operation,
) -> Result<Value, Failure> {
    if matches!(operation, Operation::Catalog) {
        return serde_json::to_value(catalog(&config.core).await).map_err(|_| Failure::Unavailable);
    }
    if let Operation::Space(p) = &operation
        && matches!(p.action, Action::Close {})
    {
        // A confirmed multi-terminal close can outlive the phone's request. Bound the
        // host-owned job count and retain its exact selection if the connection closes.
        static CLOSE_SLOT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        let permit = CLOSE_SLOT.try_acquire().map_err(|_| Failure::Busy)?;
        let core = config.core.clone();
        let selected = p.clone();
        return tokio::spawn(async move {
            let _permit = permit;
            manage_space(&core, selected).await.map(|()| json!({}))
        })
        .await
        .map_err(|_| Failure::Unconfirmed)?;
    }
    timeout(Duration::from_secs(8), async {
        match operation {
            Operation::Catalog => unreachable!(),
            Operation::Inspect(p) => tui::inspect(config, p).await,
            Operation::Create(p) => create(&config.core, p)
                .await
                .map(|binding| json!({"tab":binding})),
            Operation::Space(p) => manage_space(&config.core, p).await.map(|()| json!({})),
            Operation::Tab(p) => manage_tab(config, p).await.map(|()| json!({})),
        }
    })
    .await
    .map_err(|_| Failure::Unconfirmed)?
}

async fn connect(
    config: &CoreConfig,
    session: &str,
    expected: Option<&str>,
) -> Result<(Stream, String), Failure> {
    let connection = timeout(PROVIDER_TIMEOUT, config.connect(session))
        .await
        .map_err(|_| Failure::Unavailable)??;
    let mut stream = BufReader::new(connection);
    let hello = plain_call(&mut stream, 1, "hello", json!({"generation":1})).await?;
    let (core, _) = parse_hello(&hello)?;
    if expected.is_some_and(|id| id != core) {
        return Err(Failure::Changed);
    }
    Ok((stream, core))
}

struct Document {
    version: u64,
    value: Value,
}

impl Document {
    async fn read(stream: &mut Stream) -> Result<Self, Failure> {
        let mut result = plain_call(stream, 2, "doc.get", json!({"name":"herdr-app"})).await?;
        let version = result["version"].as_u64().ok_or(Failure::Unavailable)?;
        let mut value = result.get_mut("value").ok_or(Failure::Unavailable)?.take();
        if value.is_null() {
            value = json!({"spaces":[]});
        }
        let object = value.as_object_mut().ok_or(Failure::Unavailable)?;
        let spaces = object
            .entry("spaces")
            .or_insert_with(|| json!([]))
            .as_array()
            .ok_or(Failure::Unavailable)?;
        let mut ids = HashSet::new();
        for space in spaces {
            let id = space["id"]
                .as_str()
                .filter(|id| valid_space_id(id))
                .ok_or(Failure::Unavailable)?;
            if !ids.insert(id) || !space.get("tabs").is_none_or(Value::is_array) {
                note("desktop_document", "invalid", "space", None);
                return Err(Failure::Unavailable);
            }
            let mut tab_ids = HashSet::new();
            for tab in space["tabs"].as_array().into_iter().flatten() {
                if !tab["id"]
                    .as_str()
                    .is_some_and(|t| valid_space_id(t) && tab_ids.insert(t))
                {
                    note("desktop_document", "invalid", "tab_id", None);
                    return Err(Failure::Unavailable);
                }
            }
        }
        Ok(Self { version, value })
    }

    fn spaces(&self) -> &Vec<Value> {
        self.value["spaces"].as_array().expect("validated layout")
    }
    fn spaces_mut(&mut self) -> &mut Vec<Value> {
        self.value["spaces"]
            .as_array_mut()
            .expect("validated layout")
    }
    fn index(&self, id: &str) -> Result<usize, Failure> {
        self.spaces()
            .iter()
            .position(|s| s["id"] == id)
            .ok_or(Failure::Changed)
    }

    fn fits(&self) -> bool {
        self.version < u64::MAX
            && serde_json::to_vec(&self.value).is_ok_and(|v| v.len() <= super::CORE_DOCUMENT_BYTES)
    }

    async fn commit(self, stream: &mut Stream) -> Result<(), Failure> {
        if !self.fits() {
            return Err(Failure::Unavailable);
        }
        let version = self.version;
        let result = plain_call(
            stream,
            5,
            "doc.set",
            json!({"name":"herdr-app","version":version,"value":self.value}),
        )
        .await
        .map_err(|err| {
            if err == CoreError::Conflict {
                Failure::Changed
            } else {
                Failure::Unconfirmed
            }
        })?;
        if result["version"].as_u64().is_some_and(|v| v > version) {
            Ok(())
        } else {
            Err(Failure::Unconfirmed)
        }
    }
}

#[derive(Serialize, Default)]
struct Catalog {
    servers: Vec<Server>,
    omitted: u32,
}
#[derive(Serialize)]
struct Server {
    session: String,
    core: String,
    version: u64,
    spaces: Vec<Space>,
}
#[derive(Serialize)]
struct Space {
    id: String,
    name: String,
    tabs: u32,
    tab_items: Vec<NamedTab>,
}
#[derive(Serialize)]
struct NamedTab {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    terminals: Vec<String>,
}

async fn catalog(config: &CoreConfig) -> Catalog {
    let (names, omitted) = config.sessions();
    let mut out = Catalog {
        servers: Vec::new(),
        omitted,
    };
    let deadline = tokio::time::Instant::now() + DISCOVERY_BUDGET;
    let mut names = names.into_iter();
    // Includes the outer envelope, catalog keys and largest omitted counter.
    let mut remaining = MAX_RPC_BODY - 160;
    while let Some(name) = names.next() {
        if tokio::time::Instant::now() >= deadline {
            out.omitted = out.omitted.saturating_add(1 + names.len() as u32);
            break;
        }
        let result = tokio::time::timeout_at(
            deadline.min(tokio::time::Instant::now() + QUERY_TIMEOUT),
            async {
                let (mut stream, core) = connect(config, &name, None).await?;
                let doc = Document::read(&mut stream).await?;
                Ok::<_, Failure>((core, doc))
            },
        )
        .await;
        let Ok(Ok((core, doc))) = result else {
            out.omitted = out.omitted.saturating_add(1);
            continue;
        };
        let mut server = Server {
            session: name,
            core,
            version: doc.version,
            spaces: Vec::new(),
        };
        let header = serde_json::to_vec(&server)
            .expect("serializable catalog server")
            .len()
            + 1;
        if header > remaining {
            out.omitted = out.omitted.saturating_add(1);
            continue;
        }
        remaining -= header;
        for entry in doc.spaces().iter().take(MAX_TABS_PER_SESSION) {
            let id = entry["id"].as_str().expect("validated space id").to_owned();
            let name = entry["name"]
                .as_str()
                .and_then(sanitize_tab_label)
                .or_else(|| {
                    entry["folder"]
                        .as_str()
                        .and_then(|f| Path::new(f).file_name()?.to_str())
                        .and_then(sanitize_tab_label)
                })
                .unwrap_or_else(|| "~".to_owned());
            let tabs = entry["tabs"].as_array().map_or(0, Vec::len) as u32;
            let mut item = Space {
                id,
                name,
                tabs,
                tab_items: Vec::new(),
            };
            let size = serde_json::to_vec(&item)
                .expect("serializable catalog space")
                .len()
                + 1;
            if size > remaining {
                break;
            }
            remaining -= size;
            for (n, tab) in entry["tabs"]
                .as_array()
                .into_iter()
                .flatten()
                .take(MAX_TABS_PER_SESSION)
                .enumerate()
            {
                let Some(id) = tab["id"].as_str().filter(|s| valid_space_id(s)) else {
                    continue;
                };
                let name = tab["name"]
                    .as_str()
                    .and_then(sanitize_tab_label)
                    .unwrap_or_else(|| (n + 1).to_string());
                let mut row = NamedTab {
                    id: id.to_owned(),
                    name,
                    terminals: Vec::new(),
                };
                let bytes = serde_json::to_vec(&row).expect("serializable tab").len() + 1;
                if bytes > remaining {
                    break;
                }
                remaining -= bytes;
                // Placement hints describe local panes only. The action path independently
                // checks the exact document revision, current membership and terminal labels.
                if let Ok(refs) = members(std::slice::from_ref(tab), &server.core) {
                    row.terminals = refs.into_keys().collect();
                    let extra =
                        serde_json::to_vec(&row).expect("serializable tab").len() + 1 - bytes;
                    if extra <= remaining {
                        remaining -= extra;
                    } else {
                        row.terminals.clear();
                    }
                }
                item.tab_items.push(row);
            }
            out.omitted = out
                .omitted
                .saturating_add(tabs.saturating_sub(item.tab_items.len() as u32));
            server.spaces.push(item);
        }
        out.omitted = out
            .omitted
            .saturating_add((doc.spaces().len() - server.spaces.len()) as u32);
        out.servers.push(server);
    }
    out
}

fn fresh(prefix: &str) -> String {
    format!("{prefix}{:032x}", rand::random::<u128>())
}

async fn create(config: &CoreConfig, p: CreateParams) -> Result<String, Failure> {
    let (mut stream, core) = connect(config, &p.session, Some(&p.core)).await?;
    let mut doc = Document::read(&mut stream).await?;
    let (space, index) = match &p.destination {
        Destination::ExistingSpace { space } => (space.clone(), Some(doc.index(space)?)),
        Destination::NewSpace { .. } => (fresh("sp"), None),
    };
    let tab = fresh("tb");
    let mut params = json!({"no_parent":true,"no_notify":true,"keep":true});
    if let Some(folder) = index
        .and_then(|i| doc.spaces()[i]["folder"].as_str())
        .filter(|f| !f.is_empty())
    {
        if !Path::new(folder).is_absolute()
            || folder.len() > 4096
            || folder.chars().any(char::is_control)
        {
            return Err(Failure::Unavailable);
        }
        params["cwd"] = json!(folder);
    }
    let pane = json!({
        "id": fresh("p"),
        "type": "block",
        "content": { "terminal": "t".repeat(crate::host_protocol::MAX_TAB_ID_BYTES) }
    });
    let record = json!({
        "id": tab,
        "name": "",
        "root": { "id": tab, "type": "row", "children": [pane] }
    });
    if let Destination::NewSpace { name } = p.destination {
        doc.spaces_mut().push(json!({
            "id": space,
            "name": name,
            "folder": "",
            "tabs": [record]
        }));
    } else {
        let selected = &mut doc.spaces_mut()[index.expect("existing space")];
        let tabs = selected
            .as_object_mut()
            .expect("validated space")
            .entry("tabs")
            .or_insert_with(|| json!([]));
        tabs.as_array_mut().expect("validated tabs").push(record);
    }
    // Reserve space for the longest valid terminal address before starting a shell.
    if !doc.fits() {
        return Err(Failure::Unavailable);
    }
    let new_space = index.is_none();
    let space_index = index.unwrap_or(doc.spaces().len() - 1);
    // Publish the placed pane with a version check. A concurrently open Desktop cannot
    // adopt our shell under an automatic name before that check: it has no labels yet.
    let terminal = plain_call(&mut stream, 3, "terminal.run", params)
        .await
        .map_err(|_| Failure::Unconfirmed)?;
    let address = terminal["address"].as_str().ok_or(Failure::Unconfirmed)?;
    let binding = format!("{core}:{address}");
    if !valid_herdr_core_tab_id(&binding)
        || terminal["state"] != "live"
        || terminal["keep"] != true
        || !terminal["parent"].is_null()
    {
        return Err(Failure::Unconfirmed);
    }
    let selected = &mut doc.spaces_mut()[space_index];
    let placed_tab = selected["tabs"]
        .as_array_mut()
        .expect("prepared tabs")
        .last_mut()
        .expect("prepared tab");
    placed_tab["root"]["children"][0]["content"]["terminal"] = json!(address);
    if new_space {
        selected["folder"] = json!(terminal["cwd"].as_str().unwrap_or(""));
        // An empty folder selects Core's default directory, also used by the first shell.
        if !doc.fits() {
            doc.spaces_mut()[space_index]["folder"] = json!("");
        }
    }
    if let Err(error) = doc.commit(&mut stream).await {
        if error == Failure::Changed {
            // The shell was unplaced when it started. A different client may have
            // adopted it during the conflicting write; preserve it if ownership changed.
            let latest = Document::read(&mut stream)
                .await
                .map_err(|_| Failure::Unconfirmed)?;
            let target = BTreeMap::from([(address.to_owned(), tab.clone())]);
            ensure_exclusive(&latest, &core, &target).map_err(|_| Failure::Unconfirmed)?;
            let row = plain_call(
                &mut stream,
                4,
                "terminal.get",
                json!({ "terminal": address }),
            )
            .await
            .map_err(|_| Failure::Unconfirmed)?;
            if row["address"] != address
                || !row["labels"][super::DESKTOP_SPACE_LABEL].is_null()
                || !row["labels"][super::DESKTOP_TAB_LABEL].is_null()
            {
                return Err(Failure::Unconfirmed);
            }
            end(&mut stream, address)
                .await
                .map_err(|_| Failure::Unconfirmed)?;
        }
        return Err(error);
    }
    let labels = json!({super::DESKTOP_SPACE_LABEL:space,super::DESKTOP_TAB_LABEL:tab});
    let placed = plain_call(
        &mut stream,
        6,
        "terminal.label",
        json!({"terminal":address,"labels":labels}),
    )
    .await
    .map_err(|_| Failure::Unconfirmed)?;
    if placed["address"] != address
        || placed["labels"][super::DESKTOP_SPACE_LABEL] != space
        || placed["labels"][super::DESKTOP_TAB_LABEL] != tab
    {
        return Err(Failure::Unconfirmed);
    }
    Ok(binding)
}

async fn end(stream: &mut Stream, address: &str) -> Result<(), Failure> {
    let ended = plain_call(stream, 7, "terminal.kill", json!({"terminal":address}))
        .await
        .map_err(|_| Failure::Unconfirmed)?;
    if ended["address"] != address || ended["state"] != "finished" {
        return Err(Failure::Unconfirmed);
    }
    Ok(())
}

async fn manage_tab(config: &WorkspaceConfig, p: TabParams) -> Result<(), Failure> {
    match p.target {
        TabTarget::Core => {
            let (core, address) = p.tab.split_once(':').ok_or(Failure::Changed)?;
            let (mut stream, _) = connect(&config.core, &p.session, Some(core)).await?;
            let record =
                plain_call(&mut stream, 2, "terminal.get", json!({"terminal":address})).await?;
            if record["address"] != address || record["state"] != "live" {
                return Err(Failure::Changed);
            }
            end(&mut stream, address).await
        }
        TabTarget::Tui => tui::apply(config, p).await,
    }
}

// Only traverse Desktop layout nodes. Strings inside mod props, appearance or history
// are user data and can never nominate a terminal for termination.
fn members(tabs: &[Value], core: &str) -> Result<BTreeMap<String, String>, Failure> {
    fn content(
        c: &Value,
        core: &str,
        tab: &str,
        out: &mut BTreeMap<String, String>,
    ) -> Result<(), Failure> {
        if let Some(address) = c.get("terminal") {
            let address = address
                .as_str()
                .filter(|a| valid_herdr_core_tab_id(&format!("{core}:{a}")))
                .ok_or(Failure::Unavailable)?;
            if out.insert(address.into(), tab.into()).is_some() || out.len() > MAX_TABS_PER_SESSION
            {
                return Err(Failure::Unavailable);
            }
        } else if !(c["mod"].is_string()
            || c["agent"].is_string()
            || c["tab"].is_string()
            || c["context"].is_string())
        {
            return Err(Failure::Unavailable);
        }
        Ok(())
    }
    fn node(
        n: &Value,
        core: &str,
        tab: &str,
        out: &mut BTreeMap<String, String>,
    ) -> Result<(), Failure> {
        if let Some(floats) = n.get("floating") {
            for float in floats.as_array().ok_or(Failure::Unavailable)? {
                content(&float["content"], core, tab, out)?;
            }
        }
        match n["type"].as_str() {
            Some("row" | "column" | "stack") => {
                for child in n["children"].as_array().ok_or(Failure::Unavailable)? {
                    node(child, core, tab, out)?;
                }
            }
            Some("block") => content(&n["content"], core, tab, out)?,
            _ => return Err(Failure::Unavailable),
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    for tab in tabs {
        let id = tab["id"]
            .as_str()
            .filter(|id| valid_space_id(id))
            .ok_or(Failure::Unavailable)?;
        if let Some(root) = tab.get("root") {
            node(root, core, id, &mut out)?;
        }
    }
    Ok(out)
}

async fn manage_space(config: &CoreConfig, p: SpaceParams) -> Result<(), Failure> {
    let (mut stream, core) = connect(config, &p.session, Some(&p.core)).await?;
    let mut doc = Document::read(&mut stream).await?;
    if doc.version != p.version {
        return Err(Failure::Changed);
    }
    let index = doc.index(&p.space)?;
    let tabs = doc.spaces()[index]["tabs"].as_array();
    let tab_index = p
        .tab
        .as_ref()
        .map(|id| {
            tabs.and_then(|tabs| tabs.iter().position(|tab| tab["id"] == *id))
                .ok_or(Failure::Changed)
        })
        .transpose()?;
    match p.action {
        Action::Rename { name } => {
            let space = &mut doc.spaces_mut()[index];
            let target = if let Some(i) = tab_index {
                &mut space["tabs"][i]
            } else {
                space
            };
            target["name"] = json!(name);
            doc.commit(&mut stream).await
        }
        Action::Close {} => {
            // Keep the layout present until its processes finish. Desktop adopts live
            // labelled terminals whose layout is missing, including during slow exits.
            let original = doc.spaces()[index].clone();
            let removed = take_selected_tabs(&mut doc, index, tab_index);
            let targets = members(&removed, &core)?;
            ensure_exclusive(&doc, &core, &targets)?;
            for (address, tab) in &targets {
                still_placed(&mut stream, address, &p.space, tab).await?;
            }
            for (address, tab) in &targets {
                if !still_placed(&mut stream, address, &p.space, tab)
                    .await
                    .map_err(|_| Failure::Unconfirmed)?
                {
                    continue;
                }
                let mut latest = Document::read(&mut stream)
                    .await
                    .map_err(|_| Failure::Unconfirmed)?;
                let (i, t) = selection(&latest, &p).ok_or(Failure::Unconfirmed)?;
                let selected = take_selected_tabs(&mut latest, i, t);
                if members(&selected, &core)?.get(address) != Some(tab) {
                    return Err(Failure::Unconfirmed);
                }
                ensure_exclusive(&latest, &core, &targets).map_err(|_| Failure::Unconfirmed)?;
                // The provider exposes exact addresses and has no conditional-kill RPC.
                if still_placed(&mut stream, address, &p.space, tab)
                    .await
                    .map_err(|_| Failure::Unconfirmed)?
                {
                    end(&mut stream, address).await?;
                }
            }
            let mut latest = Document::read(&mut stream)
                .await
                .map_err(|_| Failure::Unconfirmed)?;
            let Some((i, t)) = selection(&latest, &p) else {
                // A connected Desktop prunes finished terminals from its own layout.
                return Ok(());
            };
            let latest_space = &latest.spaces()[i];
            // Desktop may already have pruned whole finished tabs. Preserve every
            // concurrent edit or newly added pane that the user did not confirm.
            if latest_space["name"] != original["name"]
                || latest_space["folder"] != original["folder"]
            {
                return Err(Failure::Unconfirmed);
            }
            let final_tabs = take_selected_tabs(&mut latest, i, t);
            if !final_tabs.iter().all(|tab| removed.contains(tab)) {
                return Err(Failure::Unconfirmed);
            }
            latest
                .commit(&mut stream)
                .await
                .map_err(|_| Failure::Unconfirmed)
        }
    }
}

/// Resolve the same tab in its original space, even while other tabs move.
fn selection(doc: &Document, p: &SpaceParams) -> Option<(usize, Option<usize>)> {
    let i = doc.index(&p.space).ok()?;
    let tab = match &p.tab {
        Some(id) => Some(
            doc.spaces()[i]["tabs"]
                .as_array()?
                .iter()
                .position(|t| t["id"] == *id)?,
        ),
        None => None,
    };
    Some((i, tab))
}

fn take_selected_tabs(doc: &mut Document, i: usize, t: Option<usize>) -> Vec<Value> {
    if let Some(t) = t
        && doc.spaces()[i]["tabs"]
            .as_array()
            .is_some_and(|tabs| tabs.len() > 1)
    {
        return vec![
            doc.spaces_mut()[i]["tabs"]
                .as_array_mut()
                .expect("selected tab")
                .remove(t),
        ];
    }
    doc.spaces_mut()
        .remove(i)
        .get_mut("tabs")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .unwrap_or_default()
}

fn ensure_exclusive(
    doc: &Document,
    core: &str,
    targets: &BTreeMap<String, String>,
) -> Result<(), Failure> {
    for space in doc.spaces() {
        if let Some(tabs) = space["tabs"].as_array()
            && members(tabs, core)?
                .keys()
                .any(|address| targets.contains_key(address))
        {
            return Err(Failure::Changed);
        }
    }
    Ok(())
}

async fn still_placed(
    stream: &mut Stream,
    address: &str,
    space: &str,
    tab: &str,
) -> Result<bool, Failure> {
    let row = match plain_call(stream, 4, "terminal.get", json!({"terminal":address})).await {
        Ok(row) => row,
        Err(CoreError::TerminalMissing) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if row["address"] != address {
        return Err(Failure::Changed);
    }
    if row["state"] == "finished" {
        return Ok(false);
    }
    if row["state"] != "live"
        || row["labels"][super::DESKTOP_SPACE_LABEL] != space
        || row["labels"][super::DESKTOP_TAB_LABEL] != tab
    {
        return Err(Failure::Changed);
    }
    Ok(true)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::host_protocol::herdr_management::{Operation, decode};

    fn operation(method: &str, params: Value) -> Operation {
        let request = json!({
            "v": 1, "type": "request", "request_id": "AAECAwQFBgcICQoLDA0ODw",
            "method": method, "params": params
        });
        decode(&serde_json::to_vec(&request).unwrap())
            .unwrap()
            .operation
    }

    #[test]
    fn close_members_traverses_only_layout_terminals() {
        let core = "a".repeat(32);
        let root = json!({
            "type": "row",
            "children": [
                { "type": "block", "content": { "mod": "files", "props": { "terminal": "t9" } } },
                { "type": "block", "content": { "terminal": "t2" } }
            ],
            "floating": [{ "id": "p3", "content": { "terminal": "t3" } }]
        });
        let mut space = json!({ "tabs": [{ "id": "tb1", "root": root }] });
        assert_eq!(
            members(space["tabs"].as_array().unwrap(), &core)
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            ["t2", "t3"]
        );
        space["tabs"][0]["root"]["children"][1]["content"]["terminal"] = json!("remote/t2");
        assert_eq!(
            members(space["tabs"].as_array().unwrap(), &core),
            Err(Failure::Unavailable)
        );
    }

    async fn slow_close_survives_request(
        workspace: &WorkspaceConfig,
        stream: &mut Stream,
        core: &str,
    ) {
        let scratch = tempfile::tempdir().unwrap();
        let mut terminals = Vec::new();
        let mut children = Vec::new();
        for index in 0..9 {
            let marker = scratch.path().join(format!("ready-{index}"));
            let row = plain_call(stream, 3, "terminal.run", json!({
                "argv": ["/bin/sh", "-c", "trap '' HUP TERM; touch \"$1\"; exec sleep 120", "sh", marker],
                "no_parent": true, "no_notify": true, "keep": true,
                "labels": { "herdr.space": "slow-space", "herdr.tab": "slow-tab" }
            })).await.unwrap();
            let address = row["address"].as_str().unwrap().to_owned();
            children.push(
                json!({ "id": fresh("p"), "type": "block", "content": { "terminal": address } }),
            );
            terminals.push(address);
        }
        timeout(Duration::from_secs(5), async {
            while std::fs::read_dir(scratch.path()).unwrap().count() != terminals.len() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("synthetic shells did not arm their signal handlers");
        let mut doc = Document::read(stream).await.unwrap();
        doc.spaces_mut().push(json!({
            "id": "slow-space", "name": "Slow", "tabs": [{
                "id": "slow-tab", "root": {"id":"slow-root","type":"row","children":children}
            }]
        }));
        doc.commit(stream).await.unwrap();
        let version = Document::read(stream).await.unwrap().version;
        let close = operation(
            "herdr.core.space.action.v1",
            json!({
                "session":"default", "core":core, "space":"slow-space", "version":version, "action":{"kind":"close"}
            }),
        );
        let started = tokio::time::Instant::now();
        let workspace = workspace.clone();
        let caller = tokio::spawn(async move { execute(&workspace, close).await });
        // Wait for a provider-confirmed effect before dropping the requesting client.
        terminals.sort();
        timeout(Duration::from_secs(5), async {
            loop {
                let row = plain_call(stream, 3, "terminal.get", json!({"terminal":terminals[0]}))
                    .await
                    .unwrap();
                if row["state"] == "finished" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .expect("first slow terminal did not stop");
        assert!(
            Document::read(stream)
                .await
                .unwrap()
                .index("slow-space")
                .is_ok()
        );
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        timeout(Duration::from_secs(25), async {
            while Document::read(stream)
                .await
                .unwrap()
                .index("slow-space")
                .is_ok()
            {
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .expect("the detached close did not finish");
        for address in terminals {
            let row = plain_call(stream, 3, "terminal.get", json!({"terminal":address}))
                .await
                .unwrap();
            assert_eq!(row["state"], "finished");
        }
        assert!(started.elapsed() > Duration::from_secs(8));
    }

    pub(crate) async fn live(config: &CoreConfig) {
        let mut workspace = WorkspaceConfig::with_binary_dirs(vec![]);
        workspace.core = config.clone();
        let catalog = execute(&workspace, Operation::Catalog).await.unwrap();
        assert_eq!(catalog["servers"].as_array().unwrap().len(), 1);
        let server = &catalog["servers"][0];
        let core = server["core"].as_str().unwrap();
        assert_eq!(server["spaces"], json!([]));
        assert_eq!(server["version"], 0);
        let new_space = |label: &str| {
            operation(
                "herdr.core.create.v1",
                json!({"session":"default","core":core,"destination":{"kind":"new_space","name":label}}),
            )
        };
        let mut stream = connect(config, "default", Some(core)).await.unwrap().0;
        let mut near_limit = Document::read(&mut stream).await.unwrap();
        near_limit.value["preserved"] = json!("");
        let used = serde_json::to_vec(&near_limit.value).unwrap().len();
        near_limit.value["preserved"] =
            json!("x".repeat(super::super::CORE_DOCUMENT_BYTES - used - 8));
        near_limit.commit(&mut stream).await.unwrap();
        for _ in 0..2 {
            assert_eq!(
                execute(&workspace, new_space("Full layout")).await,
                Err(Failure::Unavailable)
            );
            let list = plain_call(&mut stream, 3, "terminal.list", json!({ "all": true }))
                .await
                .unwrap();
            assert_eq!(list["terminals"], json!([]));
        }
        let mut near_limit = Document::read(&mut stream).await.unwrap();
        near_limit
            .value
            .as_object_mut()
            .unwrap()
            .remove("preserved");
        near_limit.commit(&mut stream).await.unwrap();
        let first = execute(&workspace, new_space("Release QA")).await.unwrap()["tab"].clone();
        let catalog = execute(&workspace, Operation::Catalog).await.unwrap();
        let server = &catalog["servers"][0];
        let entry = &server["spaces"][0];
        let space = entry["id"].clone();
        let initial = server["version"].clone();
        assert_eq!(entry["name"], "Release QA");
        assert_eq!(entry["tabs"], 1);
        let sibling = operation(
            "herdr.core.create.v1",
            json!({
                "session": "default", "core": core,
                "destination": { "kind": "existing_space", "space": space }
            }),
        );
        let second = execute(&workspace, sibling).await.unwrap()["tab"].clone();
        assert_ne!(first, second);
        let other = execute(&workspace, new_space("Keep working"))
            .await
            .unwrap()["tab"]
            .clone();
        let space_action = |version: Value, action: Value| {
            operation(
                "herdr.core.space.action.v1",
                json!({"session":"default","core":core,"space":space,"version":version,"action":action}),
            )
        };
        for _ in 0..2 {
            assert_eq!(
                execute(
                    &workspace,
                    space_action(initial.clone(), json!({"kind":"close"}))
                )
                .await,
                Err(Failure::Changed)
            );
            let stale = operation(
                "herdr.core.create.v1",
                json!({
                    "session": "default", "core": "0".repeat(32),
                    "destination": { "kind": "new_space", "name": "Wrong server" }
                }),
            );
            assert_eq!(execute(&workspace, stale).await, Err(Failure::Changed));
        }
        let mut stream = connect(config, "default", Some(core)).await.unwrap().0;
        let mut owned = Document::read(&mut stream).await.unwrap();
        owned.value["unknown_future_field"] = json!({"keep":"yes"});
        owned.commit(&mut stream).await.unwrap();
        let current = execute(&workspace, Operation::Catalog).await.unwrap();
        let renamed = execute(
            &workspace,
            space_action(
                current["servers"][0]["version"].clone(),
                json!({"kind":"rename","name":"Reviewed"}),
            ),
        )
        .await
        .unwrap();
        assert_eq!(renamed, json!({}));
        let doc = Document::read(&mut stream).await.unwrap();
        assert_eq!(doc.value["unknown_future_field"], json!({"keep":"yes"}));
        assert_eq!(doc.spaces()[0]["name"], "Reviewed");
        let targets = members(doc.spaces()[0]["tabs"].as_array().unwrap(), core).unwrap();
        for binding in [&first, &second] {
            let address = binding.as_str().unwrap().split_once(':').unwrap().1;
            let row = plain_call(&mut stream, 3, "terminal.get", json!({"terminal":address}))
                .await
                .unwrap();
            assert_eq!(row["state"], "live");
            assert_eq!(row["labels"][super::super::DESKTOP_SPACE_LABEL], space);
            assert_eq!(
                row["labels"][super::super::DESKTOP_TAB_LABEL],
                targets[address]
            );
        }
        let id = doc.spaces()[0]["tabs"][0]["id"].clone();
        let tab_action = |version: u64, action: Value| {
            let params = json!({"session":"default","core":core,"space":space,"tab":id,"version":version,"action":action});
            operation("herdr.core.tab.action.v1", params)
        };
        execute(
            &workspace,
            tab_action(doc.version, json!({"kind":"rename","name":"Builds"})),
        )
        .await
        .unwrap();
        let listed = execute(&workspace, Operation::Catalog).await.unwrap();
        assert_eq!(
            listed["servers"][0]["spaces"][0]["tab_items"][0]["name"],
            "Builds"
        );
        let first_address = first.as_str().unwrap().split_once(':').unwrap().1;
        assert_eq!(
            listed["servers"][0]["spaces"][0]["tab_items"][0]["terminals"],
            json!([first_address])
        );
        // Layout and live labels can disagree during a Desktop move. Neither observation
        // alone authorizes termination.
        let relabel = |value: &Value| {
            json!({
                "terminal": first_address,
                "labels": {super::super::DESKTOP_TAB_LABEL: value}
            })
        };
        plain_call(&mut stream, 6, "terminal.label", relabel(&json!("moved")))
            .await
            .unwrap();
        let current_version = listed["servers"][0]["version"].as_u64().unwrap();
        for _ in 0..2 {
            assert_eq!(
                execute(
                    &workspace,
                    tab_action(current_version, json!({"kind":"close"}))
                )
                .await,
                Err(Failure::Changed)
            );
        }
        plain_call(&mut stream, 6, "terminal.label", relabel(&id))
            .await
            .unwrap();
        // Duplicate one pane into a sibling tab. Even matching Herdr labels cannot
        // authorize ending a process that a second tab references.
        let mut layout = Document::read(&mut stream).await.unwrap();
        let original = layout.spaces()[0]["tabs"][1]["root"].clone();
        layout.spaces_mut()[0]["tabs"][1]["root"] = layout.spaces()[0]["tabs"][0]["root"].clone();
        layout.commit(&mut stream).await.unwrap();
        let mut duplicated = Document::read(&mut stream).await.unwrap();
        for _ in 0..2 {
            assert_eq!(
                execute(
                    &workspace,
                    tab_action(duplicated.version, json!({"kind":"close"}))
                )
                .await,
                Err(Failure::Changed)
            );
        }
        duplicated.spaces_mut()[0]["tabs"][1]["root"] = original;
        duplicated.commit(&mut stream).await.unwrap();
        let doc = Document::read(&mut stream).await.unwrap();
        execute(&workspace, tab_action(doc.version, json!({"kind":"close"})))
            .await
            .unwrap();
        let doc = Document::read(&mut stream).await.unwrap();
        assert_eq!(doc.spaces()[0]["tabs"].as_array().unwrap().len(), 1);
        let (_, second_address) = second.as_str().unwrap().split_once(':').unwrap();
        let survivor = plain_call(
            &mut stream,
            3,
            "terminal.get",
            json!({"terminal":second_address}),
        )
        .await
        .unwrap();
        assert_eq!(survivor["state"], "live");
        let alternate = other.as_str().unwrap().split_once(':').unwrap().1;
        execute(
            &workspace,
            space_action(json!(doc.version), json!({"kind":"close"})),
        )
        .await
        .unwrap();
        let confirmed = execute(&workspace, Operation::Catalog).await.unwrap();
        assert_eq!(
            confirmed["servers"][0]["spaces"].as_array().unwrap().len(),
            1
        );
        assert_eq!(confirmed["servers"][0]["spaces"][0]["name"], "Keep working");
        for address in targets.keys() {
            let ended = plain_call(&mut stream, 3, "terminal.get", json!({"terminal":address}))
                .await
                .unwrap();
            assert_eq!(ended["state"], "finished");
        }
        slow_close_survives_request(&workspace, &mut stream, core).await;
        let preserved = plain_call(
            &mut stream,
            3,
            "terminal.get",
            json!({"terminal":alternate}),
        )
        .await
        .unwrap();
        assert_eq!(preserved["state"], "live");
        let end_terminal = operation(
            "herdr.tab.action.v1",
            json!({
                "target": "herdr_core.attach", "session": "default", "tab": other,
                "action": { "kind": "close" }
            }),
        );
        execute(&workspace, end_terminal).await.unwrap();
        assert_eq!(
            plain_call(
                &mut stream,
                3,
                "terminal.get",
                json!({"terminal":alternate})
            )
            .await
            .unwrap()["state"],
            "finished"
        );
        eprintln!(
            "Core live: empty server, named space, existing space, versioned rename/close, preserved sibling and exact terminal end verified"
        );
    }
}
