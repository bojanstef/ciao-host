use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{EndpointAddr, EndpointId, RelayUrl};
use iroh_tickets::endpoint::EndpointTicket;
use qrcode::{EcLevel, QrCode, render::unicode};
use thiserror::Error;

pub const QR_URI_PREFIX: &str = "ciao://pair/";

/// Format 1 was base64url-of-JSON around a base32 ticket: 348 bytes, a 73x37 terminal QR
/// that did not fit on screen while scanning. This packs the same offer data as raw bytes
/// and lands at 57x29.
pub const QR_FORMAT_VERSION: u8 = 2;

/// version(1) + pairing_id(16) + capability(32) + expires_at(4) + host endpoint ID(32).
/// The relay URL is the variable-length tail.
const HEADER_LEN: usize = 85;
/// A relay URL longer than this is not one of ours.
const MAX_RELAY_URL_LEN: usize = 128;
pub const MAX_QR_PAYLOAD: usize = HEADER_LEN + MAX_RELAY_URL_LEN;
pub const MAX_QR_URI: usize = QR_URI_PREFIX.len() + MAX_QR_PAYLOAD.div_ceil(3) * 4;

#[derive(Debug, Clone)]
pub struct DecodedPairingOffer {
    pub ticket: EndpointTicket,
    pub pairing_id: [u8; 16],
    pub capability: [u8; 32],
    pub expires_at: u64,
}

#[derive(Debug, Error)]
pub enum QrError {
    #[error("pairing URI exceeds {MAX_QR_URI} bytes")]
    UriTooLong,
    #[error("not a Ciao pairing URI")]
    WrongScheme,
    #[error("pairing payload exceeds {MAX_QR_PAYLOAD} bytes")]
    PayloadTooLong,
    #[error("pairing payload is malformed: {0}")]
    Malformed(String),
    #[error("unsupported Ciao pairing version")]
    UnsupportedVersion,
    #[error("endpoint ticket is invalid")]
    InvalidTicket,
    #[error("pairing code expired")]
    Expired,
    #[error("pairing payload cannot fit in a QR code")]
    QrCapacity,
}

pub fn encode_pairing_uri(
    ticket: &EndpointTicket,
    pairing_id: &[u8; 16],
    capability: &[u8; 32],
    expires_at: u64,
) -> Result<String, QrError> {
    let addr = ticket.endpoint_addr();
    // An endpoint advertises one relay URL, its home relay, and that is the one the phone
    // dials. A second would only pad the QR.
    let relay = addr.relay_urls().next().ok_or(QrError::InvalidTicket)?;
    // Four-byte Unix seconds save QR modules and cover every pairing offer until 2106.
    let expires_at = u32::try_from(expires_at)
        .map_err(|_| QrError::Malformed("expiry is out of range".into()))?;

    let mut payload = Vec::with_capacity(HEADER_LEN + 32);
    payload.push(QR_FORMAT_VERSION);
    payload.extend_from_slice(pairing_id);
    payload.extend_from_slice(capability);
    payload.extend_from_slice(&expires_at.to_be_bytes());
    payload.extend_from_slice(addr.id.as_bytes());
    payload.extend_from_slice(relay.to_string().as_bytes());
    debug_assert!(payload.len() > HEADER_LEN);
    if payload.len() > MAX_QR_PAYLOAD {
        return Err(QrError::PayloadTooLong);
    }
    Ok(format!(
        "{QR_URI_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(&payload)
    ))
}

pub fn decode_pairing_uri(uri: &str, now_unix: u64) -> Result<DecodedPairingOffer, QrError> {
    if uri.len() > MAX_QR_URI {
        return Err(QrError::UriTooLong);
    }
    let encoded = uri
        .strip_prefix(QR_URI_PREFIX)
        .ok_or(QrError::WrongScheme)?;
    if encoded.is_empty() || encoded.contains(['=', '/', '+', '?', '#']) {
        return Err(QrError::Malformed("invalid base64url payload".into()));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| QrError::Malformed("invalid base64url payload".into()))?;
    if payload.len() > MAX_QR_PAYLOAD {
        return Err(QrError::PayloadTooLong);
    }
    // The relay URL tail is what makes the payload longer than the header, so an offer
    // exactly HEADER_LEN long is truncated too.
    if payload.len() <= HEADER_LEN {
        return Err(QrError::Malformed("pairing payload is truncated".into()));
    }
    if payload[0] != QR_FORMAT_VERSION {
        return Err(QrError::UnsupportedVersion);
    }
    let field = |start: usize, end: usize| -> &[u8] { &payload[start..end] };
    let pairing_id: [u8; 16] = field(1, 17).try_into().expect("fixed-width field");
    let capability: [u8; 32] = field(17, 49).try_into().expect("fixed-width field");
    let expires_at = u64::from(u32::from_be_bytes(
        field(49, 53).try_into().expect("fixed-width field"),
    ));
    let id_bytes: [u8; 32] = field(53, HEADER_LEN).try_into().expect("fixed-width field");
    let id = EndpointId::from_bytes(&id_bytes).map_err(|_| QrError::InvalidTicket)?;
    let relay = std::str::from_utf8(&payload[HEADER_LEN..])
        .ok()
        .and_then(|value| RelayUrl::from_str(value).ok())
        .ok_or(QrError::InvalidTicket)?;
    if expires_at <= now_unix {
        return Err(QrError::Expired);
    }
    Ok(DecodedPairingOffer {
        ticket: EndpointTicket::new(EndpointAddr::new(id).with_relay_url(relay)),
        pairing_id,
        capability,
        expires_at,
    })
}

pub fn decode_exact<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.is_empty() || value.contains('=') {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    bytes.try_into().ok()
}

pub fn render_terminal_qr(uri: &str) -> Result<String, QrError> {
    if uri.len() > MAX_QR_URI {
        return Err(QrError::UriTooLong);
    }
    // A terminal is a clean, high-contrast surface. Level L keeps the code compact while
    // retaining standard QR error correction and the full four-module quiet zone.
    let code = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::L)
        .map_err(|_| QrError::QrCapacity)?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .quiet_zone(true)
        .dark_color(unicode::Dense1x2::Dark)
        .light_color(unicode::Dense1x2::Light)
        .build())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use iroh::{EndpointAddr, SecretKey};
    use serde::Deserialize;

    use super::*;

    fn ticket() -> EndpointTicket {
        // As long as a production relay URL, so the size fence below measures what ships.
        EndpointTicket::new(
            EndpointAddr::new(SecretKey::generate().public())
                .with_relay_url("https://use1-1.relay.ciaooo.app".parse().unwrap()),
        )
    }

    #[test]
    fn qr_round_trip() {
        let ticket = ticket();
        let uri = encode_pairing_uri(&ticket, &[1; 16], &[2; 32], 1_000).unwrap();
        let decoded = decode_pairing_uri(&uri, 999).unwrap();
        assert_eq!(decoded.ticket.endpoint_addr(), ticket.endpoint_addr());
        assert_eq!(decoded.pairing_id, [1; 16]);
        assert_eq!(decoded.capability, [2; 32]);
        assert_eq!(decoded.expires_at, 1_000);
    }

    #[test]
    fn qr_fits_on_a_terminal_screen() {
        // The compact payload exists so the code fits on screen while the phone scans it.
        // Anything that grows the payload back past a QR version shows up here first.
        let uri = encode_pairing_uri(&ticket(), &[1; 16], &[2; 32], 1_800_000_000).unwrap();
        let rendered = render_terminal_qr(&uri).unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        let width = lines.iter().map(|line| line.chars().count()).max().unwrap();
        assert!(
            lines.len() <= 29,
            "terminal QR is {} lines tall",
            lines.len()
        );
        assert!(width <= 57, "terminal QR is {width} columns wide");
    }

    #[test]
    fn shared_qr_fixtures_are_compatible() {
        #[derive(Deserialize)]
        struct MalformedFixture {
            name: String,
            mutation: String,
            error: String,
        }
        #[derive(Deserialize)]
        struct Fixtures {
            format: String,
            reference_time: u64,
            host_endpoint_id: String,
            relay_url: String,
            valid_expires_at: u64,
            expired_expires_at: u64,
            valid_uri: String,
            expired_uri: String,
            malformed: Vec<MalformedFixture>,
        }

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase0/qr-fixtures.json"
        );
        let fixtures: Fixtures = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(fixtures.format, "generated-disposable-v2");

        let host_endpoint_id: EndpointId = fixtures.host_endpoint_id.parse().unwrap();
        let ticket = EndpointTicket::new(
            EndpointAddr::new(host_endpoint_id).with_relay_url(fixtures.relay_url.parse().unwrap()),
        );
        let pairing_id: [u8; 16] = std::array::from_fn(|index| index as u8);
        let capability: [u8; 32] = std::array::from_fn(|index| (index + 16) as u8);
        let make = |version: u8, relay: &str, truncate: bool| {
            let mut payload = vec![version];
            payload.extend_from_slice(&pairing_id);
            payload.extend_from_slice(&capability);
            payload.extend_from_slice(&(fixtures.valid_expires_at as u32).to_be_bytes());
            payload.extend_from_slice(host_endpoint_id.as_bytes());
            payload.extend_from_slice(relay.as_bytes());
            if truncate {
                payload.truncate(HEADER_LEN);
            }
            format!("{QR_URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(&payload))
        };

        let encoded =
            encode_pairing_uri(&ticket, &pairing_id, &capability, fixtures.valid_expires_at)
                .unwrap();
        assert_eq!(encoded, fixtures.valid_uri);
        let valid = decode_pairing_uri(&fixtures.valid_uri, fixtures.reference_time).unwrap();
        assert_eq!(valid.ticket.endpoint_addr().id, host_endpoint_id);

        let encoded_expired = encode_pairing_uri(
            &ticket,
            &pairing_id,
            &capability,
            fixtures.expired_expires_at,
        )
        .unwrap();
        assert_eq!(encoded_expired, fixtures.expired_uri);
        assert!(matches!(
            decode_pairing_uri(&fixtures.expired_uri, fixtures.reference_time),
            Err(QrError::Expired)
        ));

        for fixture in fixtures.malformed {
            let uri = match fixture.mutation.as_str() {
                "invalid_base64url" => format!("{QR_URI_PREFIX}%%%"),
                "wrong_version" => make(QR_FORMAT_VERSION + 1, &fixtures.relay_url, false),
                "truncated" => make(QR_FORMAT_VERSION, &fixtures.relay_url, true),
                "invalid_relay_url" => make(QR_FORMAT_VERSION, "not-a-relay-url", false),
                "oversized_payload" => make(
                    QR_FORMAT_VERSION,
                    &format!(
                        "https://relay.example.invalid/{}",
                        "a".repeat(MAX_RELAY_URL_LEN)
                    ),
                    false,
                ),
                other => panic!("unknown QR fixture mutation: {other}"),
            };
            let error = decode_pairing_uri(&uri, fixtures.reference_time).unwrap_err();
            let code = match error {
                QrError::UnsupportedVersion => "unsupported_version",
                QrError::InvalidTicket => "invalid_ticket",
                QrError::Malformed(_) => "malformed",
                QrError::UriTooLong | QrError::PayloadTooLong => "too_long",
                other => panic!("unexpected fixture error: {other}"),
            };
            assert_eq!(code, fixture.error, "{}", fixture.name);
        }
    }

    #[test]
    fn qr_rejects_wrong_scheme_oversized_and_expired_offers() {
        assert!(matches!(
            decode_pairing_uri("https://example.invalid", 0),
            Err(QrError::WrongScheme)
        ));
        assert!(matches!(
            decode_pairing_uri(
                &encode_pairing_uri(&ticket(), &[1; 16], &[2; 32], 100).unwrap(),
                100
            ),
            Err(QrError::Expired)
        ));
        assert!(matches!(
            decode_pairing_uri(
                &format!("{QR_URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(vec![2; 4096])),
                0
            ),
            Err(QrError::UriTooLong)
        ));

        assert!(matches!(
            encode_pairing_uri(&ticket(), &[1; 16], &[2; 32], u64::from(u32::MAX) + 1),
            Err(QrError::Malformed(_))
        ));

        // A relay-less ticket cannot be dialled, so it never becomes a QR.
        let bare = EndpointTicket::new(EndpointAddr::new(SecretKey::generate().public()));
        assert!(matches!(
            encode_pairing_uri(&bare, &[1; 16], &[2; 32], 100),
            Err(QrError::InvalidTicket)
        ));
    }
}
