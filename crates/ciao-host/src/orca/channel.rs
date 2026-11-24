//! Wire format adapted from Orca (MIT). See LICENSE-Orca.txt in this directory.
//! Direct Orca E2EE v2. The Unix catalog selects the local runtime and its port.
//! The independently paired public key authenticates it before any token is sent.
use super::Runtime;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use crypto_secretbox::{
    XSalsa20Poly1305,
    aead::{Aead, KeyInit},
};
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    WebSocketStream, client_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use x25519_dalek::{PublicKey, StaticSecret};

type Result<T> = std::result::Result<T, ChannelError>;
#[derive(Debug, thiserror::Error)]
#[error("Orca could not authenticate or complete the local terminal stream")]
pub(super) struct ChannelError;

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct Pairing {
    #[serde(rename = "publicKeyB64")]
    key: String,
    #[serde(rename = "deviceToken")]
    token: String,
}
impl Pairing {
    pub(super) async fn redeem(mut self, runtime: &Runtime) -> Result<Self> {
        let mut channel = Channel::connect(runtime, self.clone()).await?;
        let status = runtime
            .query("status.get", json!({}))
            .await
            .ok_or(ChannelError)?;
        if status["capabilities"]
            .as_array()
            .is_some_and(|caps| caps.iter().any(|cap| cap == "pairing.ticket-exchange.v1"))
        {
            use std::fmt::Write;
            let mut token = String::with_capacity(48);
            for byte in rand::random::<[u8; 24]>() {
                write!(token, "{byte:02x}").map_err(|_| ChannelError)?;
            }
            let id = channel
                .request("pairing.exchangeTicket", json!({"deviceToken":token}))
                .await?;
            let reply = channel.next().await?;
            if reply["id"] != id {
                return Err(ChannelError);
            }
            if reply["ok"] == true {
                self.token = token;
            } else if !matches!(
                reply["error"]["message"].as_str(),
                Some("ticket_window_closed" | "not_a_ticket")
            ) {
                return Err(ChannelError);
            }
            // Orca explicitly retains previously used access links after its exchange window.
        }
        Ok(self)
    }

    pub(super) fn decode(link: &str) -> Result<Self> {
        let code = link
            .trim()
            .strip_prefix("orca://pair?code=")
            .ok_or(ChannelError)?;
        let data = URL_SAFE_NO_PAD.decode(code).map_err(|_| ChannelError)?;
        let offer: Value = serde_json::from_slice(&data).map_err(|_| ChannelError)?;
        if offer["scope"] != "runtime" || offer["v"] != 2 {
            return Err(ChannelError);
        }
        let creds: Self = serde_json::from_value(offer).map_err(|_| ChannelError)?;
        key(&creds.key)?;
        if creds.token.is_empty() || creds.token.len() > 4096 {
            return Err(ChannelError);
        }
        Ok(creds)
    }
}

fn key(input: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(input)
        .map_err(|_| ChannelError)?
        .try_into()
        .map_err(|_| ChannelError)
}
fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
fn transcript(
    client: &[u8; 32],
    host: &[u8; 32],
    nonce: &[u8; 32],
    host_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    field(&mut out, b"domain");
    field(&mut out, b"orca-mobile-e2ee/v2/transcript");
    let mut kinds = 2u32.to_be_bytes().to_vec();
    field(&mut kinds, b"text");
    field(&mut kinds, b"binary");
    for (prefix, is_client) in [("mobile-to-desktop", true), ("desktop-to-mobile", false)] {
        let mut add = |suffix: &str, value: &[u8]| {
            field(&mut out, format!("{prefix}.{suffix}").as_bytes());
            field(&mut out, value)
        };
        add(
            "type",
            if is_client {
                b"e2ee_hello"
            } else {
                b"e2ee_ready"
            },
        );
        add("version", &2u32.to_be_bytes());
        if is_client {
            add("client-public-key", client);
            add("client-nonce", nonce);
            add("capabilities.framing", &[0, 0, 0, 1, 0, 0, 0, 2]);
            add("capabilities.payload-kinds", &kinds);
        } else {
            add("desktop-public-key", host);
            add("client-nonce-echo", nonce);
            add("desktop-nonce", host_nonce);
            add("selection.framing", &2u32.to_be_bytes());
            add("selection.payload-kinds", &kinds);
        }
        add("context.protocol", b"orca-mobile-e2ee");
        add("context.initiator", b"mobile");
        add("context.responder", b"desktop");
        add("context.transport", b"direct");
        add("context.relay-host-id", b"");
    }
    out
}

struct Cipher {
    key: XSalsa20Poly1305,
    session: [u8; 32],
    direction: u8,
    counter: u64,
}
impl Cipher {
    fn framing(&self) -> ([u8; 24], [u8; 42]) {
        let mut nonce = [0; 24];
        nonce[..12].copy_from_slice(&self.session[..12]);
        nonce[12] = 2;
        nonce[13] = self.direction;
        nonce[16..].copy_from_slice(&self.counter.to_be_bytes());
        let mut header = [0; 42];
        header[..32].copy_from_slice(&self.session);
        header[32] = self.direction;
        header[34..].copy_from_slice(&self.counter.to_be_bytes());
        (nonce, header)
    }
    fn seal(&mut self, value: &Value) -> Result<String> {
        let (nonce, header) = self.framing();
        let mut payload = header.to_vec();
        serde_json::to_writer(&mut payload, value).map_err(|_| ChannelError)?;
        let mut frame = nonce.to_vec();
        frame.extend(
            self.key
                .encrypt((&nonce).into(), payload.as_slice())
                .map_err(|_| ChannelError)?,
        );
        self.counter = self.counter.checked_add(1).ok_or(ChannelError)?;
        Ok(STANDARD.encode(frame))
    }
    fn open(&mut self, text: &str) -> Result<Value> {
        let (nonce, header) = self.framing();
        let bytes = STANDARD.decode(text).map_err(|_| ChannelError)?;
        let encrypted = bytes.strip_prefix(nonce.as_slice()).ok_or(ChannelError)?;
        let plaintext = self
            .key
            .decrypt((&nonce).into(), encrypted)
            .map_err(|_| ChannelError)?;
        let payload = plaintext
            .strip_prefix(header.as_slice())
            .ok_or(ChannelError)?;
        self.counter = self.counter.checked_add(1).ok_or(ChannelError)?;
        serde_json::from_slice(payload).map_err(|_| ChannelError)
    }
}

type Socket = WebSocketStream<TcpStream>;
async fn read_text(socket: &mut Socket) -> Result<String> {
    loop {
        match socket
            .next()
            .await
            .ok_or(ChannelError)?
            .map_err(|_| ChannelError)?
        {
            Message::Text(text) => return Ok(text.to_string()),
            Message::Ping(_) => socket.flush().await.map_err(|_| ChannelError)?,
            Message::Pong(_) => {}
            _ => return Err(ChannelError),
        }
    }
}
pub(super) struct Channel {
    socket: Socket,
    send: Cipher,
    recv: Cipher,
    token: String,
    runtime: String,
}
impl Channel {
    pub(super) async fn connect(rt: &Runtime, pairing: Pairing) -> Result<Self> {
        let endpoint = rt
            .metadata
            .transports
            .iter()
            .find(|t| t.kind == "websocket")
            .and_then(|t| t.endpoint.to_str())
            .ok_or(ChannelError)?;
        let uri: tokio_tungstenite::tungstenite::http::Uri =
            endpoint.parse().map_err(|_| ChannelError)?;
        let port = uri.port_u16().ok_or(ChannelError)?;
        if uri.scheme_str() != Some("ws") {
            return Err(ChannelError);
        }
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        let tcp = TcpStream::connect(addr).await.map_err(|_| ChannelError)?;
        let cfg = WebSocketConfig::default()
            .max_message_size(Some(8 << 20))
            .max_frame_size(Some(8 << 20));
        let (mut socket, _) = client_async_with_config(format!("ws://{addr}/"), tcp, Some(cfg))
            .await
            .map_err(|_| ChannelError)?;
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let client = PublicKey::from(&secret).to_bytes();
        let host = key(&pairing.key)?;
        let nonce = rand::random::<[u8; 32]>();
        let context = json!({"protocol":"orca-mobile-e2ee","initiator":"mobile","responder":"desktop","transport":"direct"});
        let hello = json!({"type":"e2ee_hello","v":2,"clientPublicKeyB64":STANDARD.encode(client),"clientNonceB64":STANDARD.encode(nonce),
            "capabilities":{"framing":[2],"payloadKinds":["text","binary"]},"context":context});
        socket
            .send(Message::text(hello.to_string()))
            .await
            .map_err(|_| ChannelError)?;
        let ready: Value =
            serde_json::from_str(&read_text(&mut socket).await?).map_err(|_| ChannelError)?;
        let host_nonce = key(ready["desktopNonceB64"].as_str().ok_or(ChannelError)?)?;
        if ready
            != json!({"type":"e2ee_ready","v":2,"desktopPublicKeyB64":pairing.key,"clientNonceB64":STANDARD.encode(nonce),"desktopNonceB64":STANDARD.encode(host_nonce),"selection":{"framing":2,"payloadKinds":["text","binary"]},"context":context})
        {
            return Err(ChannelError);
        }
        let shared = secret.diffie_hellman(&PublicKey::from(host));
        if !shared.was_contributory() {
            return Err(ChannelError);
        }
        let precomputed = salsa20::hsalsa::<salsa20::cipher::consts::U10>(
            shared.as_bytes().into(),
            &Default::default(),
        );
        let hash = Sha256::digest(transcript(&client, &host, &nonce, &host_nonce));
        let salt = Sha256::new()
            .chain_update(b"orca-mobile-e2ee/v2/salt\0")
            .chain_update(nonce)
            .chain_update(host_nonce)
            .finalize();
        let mut keys = [0; 96];
        Hkdf::<Sha256>::new(Some(&salt), &precomputed)
            .expand(
                &[b"orca-mobile-e2ee/v2/session\0".as_slice(), &hash].concat(),
                &mut keys,
            )
            .map_err(|_| ChannelError)?;
        let cipher = |direction: u8| -> Result<Cipher> {
            let start = usize::from(direction) * 32;
            Ok(Cipher {
                direction,
                counter: 0,
                session: keys[64..].try_into().map_err(|_| ChannelError)?,
                key: XSalsa20Poly1305::new_from_slice(&keys[start..start + 32])
                    .map_err(|_| ChannelError)?,
            })
        };
        let mut result = Self {
            socket,
            send: cipher(0)?,
            recv: cipher(1)?,
            token: pairing.token,
            runtime: rt.metadata.runtime_id.clone(),
        };
        let hash = STANDARD.encode(hash);
        result.send_json(&json!({"type":"e2ee_auth","v":2,"deviceToken":result.token,"transcriptHashB64":hash})).await?;
        if result.read_json().await?
            != json!({"type":"e2ee_authenticated","v":2,"transcriptHashB64":hash})
        {
            return Err(ChannelError);
        }
        let id = result.request("status.get", json!({"probe":true})).await?;
        let frame = result.next().await?;
        if frame["id"] != id
            || frame["ok"] != true
            || frame["result"]["runtimeId"] != result.runtime
        {
            return Err(ChannelError);
        }
        Ok(result)
    }
    async fn send_json(&mut self, value: &Value) -> Result<()> {
        let text = self.send.seal(value)?;
        self.socket
            .send(Message::text(text))
            .await
            .map_err(|_| ChannelError)
    }
    async fn read_json(&mut self) -> Result<Value> {
        let text = read_text(&mut self.socket).await?;
        self.recv.open(&text)
    }
    pub(super) async fn next(&mut self) -> Result<Value> {
        loop {
            let frame = self.read_json().await?;
            if frame["_keepalive"] == true {
                continue;
            }
            if frame["_meta"]["runtimeId"] != self.runtime {
                return Err(ChannelError);
            }
            return Ok(frame);
        }
    }
    pub(super) async fn request(&mut self, method: &str, params: Value) -> Result<String> {
        let id = crate::protocol::base64url(&rand::random::<[u8; 16]>());
        self.send_json(&json!({"id":id,"deviceToken":self.token,"method":method,"params":params}))
            .await?;
        Ok(id)
    }
}
