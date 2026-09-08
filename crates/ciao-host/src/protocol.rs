use std::io;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

pub const PROTOCOL_VERSION: u8 = 1;
pub const PAIRING_ALPN: &[u8] = b"ciao/pair/1";
pub const MAX_FRAME_BODY: usize = 16 * 1024;
pub const HEARTBEAT_INTERVAL_MS: u64 = 3_000;
pub const HEARTBEAT_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireMessage {
    PairRequest {
        v: u8,
        pairing_id: String,
        capability: String,
        client_nonce: String,
        /// Device's ephemeral X25519 share (ADR 005). Public by design; see `kex_shared`.
        client_kex: String,
    },
    PairAccepted {
        v: u8,
        host_endpoint_id: String,
        installation_endpoint_id: String,
        server_nonce: String,
        expires_at: u64,
        transcript_hash: String,
        heartbeat_interval_ms: u64,
        /// Host's ephemeral X25519 share (ADR 005).
        server_kex: String,
    },
    PairRejected {
        v: u8,
        code: String,
        message: String,
    },
    Ping {
        v: u8,
        sequence: u64,
    },
    Pong {
        v: u8,
        sequence: u64,
    },
}

impl WireMessage {
    pub fn version(&self) -> u8 {
        match self {
            Self::PairRequest { v, .. }
            | Self::PairAccepted { v, .. }
            | Self::PairRejected { v, .. }
            | Self::Ping { v, .. }
            | Self::Pong { v, .. } => *v,
        }
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("frame body cannot be empty")]
    ZeroLength,
    #[error("frame body exceeds {MAX_FRAME_BODY} bytes")]
    Oversized,
    #[error("stream ended while reading a frame")]
    Truncated,
    #[error("frame is not valid JSON: {0}")]
    MalformedJson(String),
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("unknown protocol message type")]
    UnknownMessageType,
    #[error("unexpected protocol message order")]
    UnexpectedMessageOrder,
    #[error("stream I/O failed: {0}")]
    Io(#[from] io::Error),
}

pub fn encode_frame(message: &WireMessage) -> Result<Vec<u8>, ProtocolError> {
    let body = serde_json::to_vec(message)
        .map_err(|error| ProtocolError::MalformedJson(error.to_string()))?;
    if body.is_empty() {
        return Err(ProtocolError::ZeroLength);
    }
    if body.len() > MAX_FRAME_BODY {
        return Err(ProtocolError::Oversized);
    }

    let mut encoded = Vec::with_capacity(4 + body.len());
    encoded.extend_from_slice(&(body.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

pub fn decode_message(body: &[u8]) -> Result<WireMessage, ProtocolError> {
    if body.is_empty() {
        return Err(ProtocolError::ZeroLength);
    }
    if body.len() > MAX_FRAME_BODY {
        return Err(ProtocolError::Oversized);
    }

    let value: Value = serde_json::from_slice(body)
        .map_err(|error| ProtocolError::MalformedJson(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolError::MalformedJson("message must be an object".into()))?;
    let version = object
        .get("v")
        .and_then(Value::as_u64)
        .ok_or_else(|| ProtocolError::MalformedJson("v must be an integer".into()))?;
    if version != u64::from(PROTOCOL_VERSION) {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let message_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolError::MalformedJson("type must be a string".into()))?;
    if !matches!(
        message_type,
        "pair_request" | "pair_accepted" | "pair_rejected" | "ping" | "pong"
    ) {
        return Err(ProtocolError::UnknownMessageType);
    }

    serde_json::from_value(value).map_err(|error| ProtocolError::MalformedJson(error.to_string()))
}

pub async fn read_frame<R>(reader: &mut R) -> Result<WireMessage, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(ProtocolError::Truncated);
        }
        Err(error) => return Err(ProtocolError::Io(error)),
    }
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(ProtocolError::ZeroLength);
    }
    if length > MAX_FRAME_BODY {
        return Err(ProtocolError::Oversized);
    }

    let mut body = vec![0_u8; length];
    match reader.read_exact(&mut body).await {
        Ok(_) => decode_message(&body),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Err(ProtocolError::Truncated),
        Err(error) => Err(ProtocolError::Io(error)),
    }
}

pub async fn write_frame<W>(writer: &mut W, message: &WireMessage) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&encode_frame(message)?).await?;
    writer.flush().await?;
    Ok(())
}

#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<WireMessage>, ProtocolError> {
        const MAX_BUFFERED: usize = (MAX_FRAME_BODY + 4) * 4;
        if self.buffer.len().saturating_add(bytes.len()) > MAX_BUFFERED {
            return Err(ProtocolError::Oversized);
        }
        self.buffer.extend_from_slice(bytes);

        let mut messages = Vec::new();
        loop {
            if self.buffer.len() < 4 {
                break;
            }
            let length =
                u32::from_be_bytes(self.buffer[..4].try_into().expect("four-byte header")) as usize;
            if length == 0 {
                return Err(ProtocolError::ZeroLength);
            }
            if length > MAX_FRAME_BODY {
                return Err(ProtocolError::Oversized);
            }
            if self.buffer.len() < 4 + length {
                break;
            }
            let message = decode_message(&self.buffer[4..4 + length])?;
            self.buffer.drain(..4 + length);
            messages.push(message);
        }
        Ok(messages)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostMessageState {
    AwaitingPairRequest,
    AwaitingFirstPing,
    Paired { last_sequence: u64 },
}

impl HostMessageState {
    pub fn accept(self, message: &WireMessage) -> Result<Self, ProtocolError> {
        match (self, message) {
            (Self::AwaitingPairRequest, WireMessage::PairRequest { .. }) => {
                Ok(Self::AwaitingFirstPing)
            }
            (Self::AwaitingFirstPing, WireMessage::Ping { sequence: 1, .. }) => {
                Ok(Self::Paired { last_sequence: 1 })
            }
            (
                Self::Paired { last_sequence },
                WireMessage::Ping {
                    sequence,
                    v: PROTOCOL_VERSION,
                },
            ) if *sequence > last_sequence => Ok(Self::Paired {
                last_sequence: *sequence,
            }),
            _ => Err(ProtocolError::UnexpectedMessageOrder),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn pairing_transcript_hash(
    pairing_id: &[u8; 16],
    capability_hash: &[u8; 32],
    host_endpoint_id: &[u8; 32],
    installation_endpoint_id: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    expires_at: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ciao-pair-v1\0");
    hasher.update(pairing_id);
    hasher.update(capability_hash);
    hasher.update(host_endpoint_id);
    hasher.update(installation_endpoint_id);
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    hasher.update(expires_at.to_be_bytes());
    hasher.finalize().into()
}

/// Public half of an ephemeral X25519 share.
pub fn kex_public(secret: &[u8; 32]) -> [u8; 32] {
    x25519(*secret, X25519_BASEPOINT_BYTES)
}

/// The Diffie-Hellman output for a peer's share, or `None` if the peer sent a low-order point.
///
/// `x25519` clamps the scalar but does not reject small-subgroup input, and an all-zero output
/// is a constant anyone can produce (RFC 7748 §6.1). Refusing it keeps the notification key
/// unguessable rather than merely present.
pub fn kex_shared(secret: &[u8; 32], peer_public: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = x25519(*secret, *peer_public);
    (!bool::from(shared.ct_eq(&[0_u8; 32]))).then_some(shared)
}

/// A short one-way tag for a notification key, safe to log so the two sides of a pairing can be
/// compared without either of them ever printing key material.
pub fn notification_key_fingerprint(key: &[u8; 32]) -> String {
    let digest: [u8; 32] = Sha256::digest(key).into();
    digest[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The ADR 005 notification key, held by host and paired device and by nobody else.
///
/// It is *not* derived from `pairing_transcript_hash` alone. Every input to that hash crosses
/// the wire, the digest is sent back in `pair_accepted`, and it is stored in plaintext in
/// `paired-devices.json` — so a transcript-derived key would be reproducible by anything that
/// reads either. The secrecy comes from the Diffie-Hellman output, which is never transmitted;
/// the transcript is mixed in so the key is bound to this exact pairing.
pub fn notification_key(shared: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ciao-notify-v1\0");
    hasher.update(shared);
    hasher.update(transcript_hash);
    hasher.finalize().into()
}

pub fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde::Deserialize;

    use super::*;
    use crate::qr::decode_exact;

    fn request() -> WireMessage {
        WireMessage::PairRequest {
            v: 1,
            pairing_id: base64url(&[1; 16]),
            capability: base64url(&[2; 32]),
            client_nonce: base64url(&[3; 32]),
            client_kex: base64url(&kex_public(&[4; 32])),
        }
    }

    fn hex_32(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        bytes
    }

    #[test]
    fn fragmented_and_coalesced_frames_decode() {
        let first = encode_frame(&request()).unwrap();
        let second = encode_frame(&WireMessage::Ping { v: 1, sequence: 1 }).unwrap();
        let mut decoder = FrameDecoder::default();

        assert!(decoder.push(&first[..2]).unwrap().is_empty());
        assert!(decoder.push(&first[2..9]).unwrap().is_empty());
        let mut tail = first[9..].to_vec();
        tail.extend_from_slice(&second);
        let decoded = decoder.push(&tail).unwrap();
        assert_eq!(
            decoded,
            vec![request(), WireMessage::Ping { v: 1, sequence: 1 }]
        );
    }

    #[test]
    fn frame_rejects_zero_oversized_and_bad_json() {
        let mut decoder = FrameDecoder::default();
        assert!(matches!(
            decoder.push(&0_u32.to_be_bytes()),
            Err(ProtocolError::ZeroLength)
        ));

        let mut decoder = FrameDecoder::default();
        assert!(matches!(
            decoder.push(&((MAX_FRAME_BODY + 1) as u32).to_be_bytes()),
            Err(ProtocolError::Oversized)
        ));

        let body = b"not-json";
        let mut encoded = (body.len() as u32).to_be_bytes().to_vec();
        encoded.extend_from_slice(body);
        let mut decoder = FrameDecoder::default();
        assert!(matches!(
            decoder.push(&encoded),
            Err(ProtocolError::MalformedJson(_))
        ));
    }

    #[test]
    fn message_order_is_enforced() {
        let state = HostMessageState::AwaitingPairRequest;
        assert!(
            state
                .accept(&WireMessage::Ping { v: 1, sequence: 1 })
                .is_err()
        );
        let state = state.accept(&request()).unwrap();
        assert!(
            state
                .accept(&WireMessage::Ping { v: 1, sequence: 2 })
                .is_err()
        );
        let state = state
            .accept(&WireMessage::Ping { v: 1, sequence: 1 })
            .unwrap();
        assert!(
            state
                .accept(&WireMessage::Ping { v: 1, sequence: 1 })
                .is_err()
        );
        assert!(
            state
                .accept(&WireMessage::Ping { v: 1, sequence: 2 })
                .is_ok()
        );
    }

    #[test]
    fn canonical_transcript_matches_shared_fixture() {
        #[derive(Deserialize)]
        struct Fixture {
            pairing_id: String,
            capability_hash: String,
            host_endpoint_id: String,
            installation_endpoint_id: String,
            client_nonce: String,
            server_nonce: String,
            expires_at: u64,
            transcript_hash: String,
        }
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase0/transcript-v1.json"
        );
        let fixture: Fixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let actual = pairing_transcript_hash(
            &decode_exact::<16>(&fixture.pairing_id).unwrap(),
            &decode_exact::<32>(&fixture.capability_hash).unwrap(),
            &hex_32(&fixture.host_endpoint_id),
            &hex_32(&fixture.installation_endpoint_id),
            &decode_exact::<32>(&fixture.client_nonce).unwrap(),
            &decode_exact::<32>(&fixture.server_nonce).unwrap(),
            fixture.expires_at,
        );
        assert_eq!(base64url(&actual), fixture.transcript_hash);
    }

    #[test]
    fn canonical_notification_key_matches_shared_fixture() {
        #[derive(Deserialize)]
        struct Fixture {
            client_secret: String,
            client_kex: String,
            server_secret: String,
            server_kex: String,
            shared_secret: String,
            transcript_hash: String,
            notification_key: String,
        }

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase0/notification-key-v1.json"
        );
        let fixture: Fixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let client_secret = hex_32(&fixture.client_secret);
        let server_secret = hex_32(&fixture.server_secret);
        let client_kex = hex_32(&fixture.client_kex);
        let server_kex = hex_32(&fixture.server_kex);
        let transcript = decode_exact::<32>(&fixture.transcript_hash).unwrap();

        assert_eq!(kex_public(&client_secret), client_kex);
        assert_eq!(kex_public(&server_secret), server_kex);
        let shared = kex_shared(&server_secret, &client_kex).unwrap();
        assert_eq!(shared, hex_32(&fixture.shared_secret));
        assert_eq!(kex_shared(&client_secret, &server_kex).unwrap(), shared);
        assert_eq!(
            base64url(&notification_key(&shared, &transcript)),
            fixture.notification_key
        );
    }

    #[test]
    fn both_sides_derive_one_key_that_a_changed_transcript_changes() {
        let client_secret = rand::random::<[u8; 32]>();
        let server_secret = rand::random::<[u8; 32]>();
        let transcript = pairing_transcript_hash(
            &[1; 16], &[2; 32], &[3; 32], &[4; 32], &[5; 32], &[6; 32], 7,
        );

        // Each side sees only the peer's public share and still reaches the same bytes.
        let device = notification_key(
            &kex_shared(&client_secret, &kex_public(&server_secret)).unwrap(),
            &transcript,
        );
        let host = notification_key(
            &kex_shared(&server_secret, &kex_public(&client_secret)).unwrap(),
            &transcript,
        );
        assert_eq!(device, host);

        // One different transcript field — here the server nonce — is a different key, so a
        // reflected or replayed share cannot revive an earlier pairing's key.
        let other = pairing_transcript_hash(
            &[1; 16], &[2; 32], &[3; 32], &[4; 32], &[5; 32], &[9; 32], 7,
        );
        assert_ne!(
            host,
            notification_key(
                &kex_shared(&server_secret, &kex_public(&client_secret)).unwrap(),
                &other,
            )
        );

        // A low-order share yields a constant, so it is refused rather than keyed on.
        assert!(kex_shared(&server_secret, &[0; 32]).is_none());
    }

    #[test]
    fn the_notification_key_reaches_no_pairing_frame() {
        let client_secret = rand::random::<[u8; 32]>();
        let server_secret = rand::random::<[u8; 32]>();
        let transcript = pairing_transcript_hash(
            &[1; 16], &[2; 32], &[3; 32], &[4; 32], &[5; 32], &[6; 32], 7,
        );
        let key = notification_key(
            &kex_shared(&server_secret, &kex_public(&client_secret)).unwrap(),
            &transcript,
        );

        let frames = [
            encode_frame(&WireMessage::PairRequest {
                v: PROTOCOL_VERSION,
                pairing_id: base64url(&[1; 16]),
                capability: base64url(&[2; 32]),
                client_nonce: base64url(&[5; 32]),
                client_kex: base64url(&kex_public(&client_secret)),
            })
            .unwrap(),
            encode_frame(&WireMessage::PairAccepted {
                v: PROTOCOL_VERSION,
                host_endpoint_id: "a".repeat(64),
                installation_endpoint_id: "b".repeat(64),
                server_nonce: base64url(&[6; 32]),
                expires_at: 7,
                transcript_hash: base64url(&transcript),
                heartbeat_interval_ms: HEARTBEAT_INTERVAL_MS,
                server_kex: base64url(&kex_public(&server_secret)),
            })
            .unwrap(),
        ];
        for frame in &frames {
            assert!(
                !frame.windows(32).any(|window| window == key),
                "raw notification key bytes are on the wire"
            );
            let encoded = base64url(&key);
            assert!(
                !String::from_utf8_lossy(frame).contains(&encoded),
                "encoded notification key is on the wire"
            );
            // Neither is either side's Diffie-Hellman secret.
            for secret in [&client_secret, &server_secret] {
                assert!(!frame.windows(32).any(|window| window == secret));
                assert!(!String::from_utf8_lossy(frame).contains(&base64url(secret)));
            }
        }
    }

    #[test]
    fn unsupported_version_is_distinct() {
        let body = br#"{"v":2,"type":"ping","sequence":1}"#;
        assert!(matches!(
            decode_message(body),
            Err(ProtocolError::UnsupportedVersion)
        ));
    }
}
