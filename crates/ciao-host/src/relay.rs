//! The one place the host's relay map is defined.
//!
//! Both relays are Ciao-operated; see the README's relay-access limitations. This replaces
//! Number 0's relays for packet relaying only — address publication and resolution still go
//! through their `dns.iroh.link`, because `relay_mode` overrides nothing else.

use anyhow::{Context, Result, bail};
use iroh::{RelayConfig, RelayMap};
use iroh_relay::RelayQuicConfig;

/// Region-coded, never provider- or datacenter-coded. These are compiled into shipped clients,
/// so a hostname here can never be retired once an install has dialled it.
pub const RELAY_URLS: [&str; 2] = [
    "https://use1-1.relay.ciaooo.app",
    "https://usw2-1.relay.ciaooo.app",
];

/// `RelayConfig::quic` defaults to `None`, and `None` disables QUIC address discovery for that
/// relay — silently giving up the exact capability UDP 7842 is open for. Always pass it.
pub const QUIC_PORT: u16 = 7842;

/// Baked in at build time from the environment; see the README's relay-access limitations.
const TOKEN: Option<&str> = option_env!("CIAO_RELAY_TOKEN");

/// Discovering the token is missing at daemon startup is already too late: by then the release
/// has been packaged and possibly distributed, and every host it reached refuses to start. Fail
/// the build instead. `configured_map` still checks at runtime for the debug path.
#[cfg(not(debug_assertions))]
const _: () = match TOKEN {
    Some(token) => assert!(
        !token.is_empty(),
        "CIAO_RELAY_TOKEN was empty when building a release binary; see apps/ios/.env.example"
    ),
    None => panic!(
        "CIAO_RELAY_TOKEN must be set when building a release binary; see apps/ios/.env.example"
    ),
};

/// `Ok(None)` means "keep whatever relays the preset configured". Only a debug build can ever
/// receive it, so a release binary can never quietly fall back to Number 0's relays.
pub fn configured_map() -> Result<Option<RelayMap>> {
    match TOKEN.filter(|token| !token.is_empty()) {
        Some(token) => Ok(Some(map_with_token(token)?)),
        None if cfg!(debug_assertions) => {
            tracing::warn!(
                "CIAO_RELAY_TOKEN was unset when this debug binary was built; relaying through \
                 Number 0 instead of the Ciao relays"
            );
            Ok(None)
        }
        None => bail!(
            "CIAO_RELAY_TOKEN was unset when this release binary was built; refusing to relay \
             through Number 0"
        ),
    }
}

fn map_with_token(token: &str) -> Result<RelayMap> {
    let configs = RELAY_URLS
        .iter()
        .map(|url| {
            let parsed = url
                .parse()
                .with_context(|| format!("parse relay URL {url}"))?;
            Ok(
                RelayConfig::new(parsed, Some(RelayQuicConfig::new(QUIC_PORT)))
                    .with_auth_token(token),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(configs.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::{Endpoint, RelayMode, Watcher, endpoint::presets};
    use tokio::time::timeout;

    use super::*;

    /// Deliberately literal, not `RELAY_URLS`/`QUIC_PORT`. Asserting against the same constants
    /// the map is built from moves both sides of the comparison together, and a test that
    /// cannot fail when the constant is wrong is not a fence. These two hostnames and this port
    /// are a contract with the deployed relays' TLS certificates and firewall rules.
    const PINNED_URLS: [&str; 2] = [
        "https://use1-1.relay.ciaooo.app",
        "https://usw2-1.relay.ciaooo.app",
    ];
    const PINNED_QUIC_PORT: u16 = 7842;

    fn urls_of(map: &RelayMap) -> Vec<String> {
        map.urls::<Vec<_>>()
            .iter()
            .map(|url| url.to_string().trim_end_matches('/').to_string())
            .collect()
    }

    #[test]
    fn map_carries_both_relays_with_the_quic_port_and_the_token() {
        let map = map_with_token("test-token").expect("build the relay map");
        let urls = urls_of(&map);
        assert_eq!(urls.len(), 2, "expected exactly two relays, got {urls:?}");
        for expected in PINNED_URLS {
            assert!(
                urls.iter().any(|url| url == expected),
                "{expected} missing from {urls:?}"
            );
        }
        for relay in map.relays::<Vec<_>>() {
            assert_eq!(
                relay.quic.as_ref().map(|quic| quic.port),
                Some(PINNED_QUIC_PORT),
                "{} lost its QUIC address-discovery port",
                relay.url
            );
            assert_eq!(
                relay.auth_token.as_deref(),
                Some("test-token"),
                "{} would be dialled unauthenticated",
                relay.url
            );
        }
    }

    #[test]
    fn map_never_inherits_a_number_0_relay() {
        let map = map_with_token("test-token").expect("build the relay map");
        assert!(
            urls_of(&map)
                .iter()
                .all(|url| !url.contains("iroh.link") && !url.contains("n0.")),
            "a Number 0 relay survived into the custom map: {:?}",
            urls_of(&map)
        );
    }

    const PROBE_ALPN: &[u8] = b"ciao/relay/probe/1";

    fn probe_endpoint(token: &str, alpns: Vec<Vec<u8>>) -> iroh::endpoint::Builder {
        // `clear_ip_transports` forces every packet onto a relay, so a direct path can never
        // make these pass while the relays themselves are broken.
        Endpoint::builder(presets::N0)
            .relay_mode(RelayMode::Custom(
                map_with_token(token).expect("build the relay map"),
            ))
            .clear_ip_transports()
            .alpns(alpns)
    }

    /// Live validation of the deployed relays. Ignored by default: this requires explicit
    /// operator authorization, network access, and a legitimately supplied admission token.
    /// Public source compilation does not grant production relay access.
    ///
    /// A relay that starts cleanly and then aborts on the first QUIC packet passes every check
    /// short of this one; that is exactly how the musl build reached production.
    #[tokio::test]
    #[ignore = "dials the deployed relays; needs CIAO_RELAY_TOKEN"]
    async fn deployed_relays_carry_a_forced_relay_round_trip() {
        let token = std::env::var("CIAO_RELAY_TOKEN")
            .expect("CIAO_RELAY_TOKEN must be set to probe the deployed relays");

        let host = probe_endpoint(&token, vec![PROBE_ALPN.to_vec()])
            .bind()
            .await
            .expect("bind the probe host");
        let client = probe_endpoint(&token, Vec::new())
            .bind()
            .await
            .expect("bind the probe client");
        timeout(Duration::from_secs(60), host.online())
            .await
            .expect("probe host never became relay-online");
        timeout(Duration::from_secs(60), client.online())
            .await
            .expect("probe client never became relay-online");

        let host_addr = host.addr();
        assert_eq!(
            host_addr.relay_urls().count(),
            1,
            "the probe host did not advertise exactly one relay"
        );
        assert_eq!(
            host_addr.ip_addrs().count(),
            0,
            "a forced-relay host advertised a direct IP path"
        );

        let server = tokio::spawn({
            let host = host.clone();
            async move {
                let incoming = timeout(Duration::from_secs(20), host.accept())
                    .await
                    .expect("the probe server timed out accepting")
                    .expect("the probe server endpoint closed");
                let connection = incoming.await.expect("accept the relayed connection");
                let (mut send, mut recv) = connection
                    .accept_bi()
                    .await
                    .expect("accept the probe stream");
                let request = recv.read_to_end(64).await.expect("read the probe request");
                assert_eq!(request.as_slice(), b"ping".as_slice());
                send.write_all(b"pong")
                    .await
                    .expect("write the probe response");
                send.finish().expect("finish the probe response");
                // finish() marks the stream complete but does not flush it. Returning here drops
                // `connection`, and dropping one closes it with code 0 — which the client reads
                // as "closed by peer" instead of the response.
                connection.closed().await;
            }
        });

        let connection = timeout(
            Duration::from_secs(20),
            client.connect(host_addr, PROBE_ALPN),
        )
        .await
        .expect("the relayed connect timed out")
        .expect("connect over the relay");
        let (mut send, mut recv) = connection.open_bi().await.expect("open the probe stream");
        send.write_all(b"ping")
            .await
            .expect("write the probe request");
        send.finish().expect("finish the probe request");
        let response = recv.read_to_end(64).await.expect("read the probe response");
        assert_eq!(response.as_slice(), b"pong".as_slice());

        // The server holds its connection until the peer departs, so close before joining.
        client.close().await;
        server.await.expect("join the probe server");
        host.close().await;
    }

    /// The relays default to `access = "everyone"`. This is the check that the deployed
    /// `access.shared_token` is actually in force, and it needs no real token to run.
    #[tokio::test]
    #[ignore = "dials the deployed relays"]
    async fn deployed_relays_refuse_a_wrong_token() {
        let endpoint = probe_endpoint("known-wrong-token", Vec::new())
            .bind()
            .await
            .expect("bind the probe endpoint");
        let online = timeout(Duration::from_secs(10), endpoint.online()).await;
        // Not `online.is_err()` alone: a relay that is simply down also fails to come online, so
        // that assertion would pass against dead relays — the one outcome this suite exists to
        // catch. Insist the refusal was an authentication decision the relay was alive to make.
        let statuses = endpoint.home_relay_status().get();
        let errors: Vec<String> = statuses
            .iter()
            .filter_map(|status| status.last_error().map(|error| format!("{error:#}")))
            .collect();
        endpoint.close().await;

        assert!(
            online.is_err(),
            "the deployed relays admitted a wrong token"
        );
        assert!(
            !statuses.is_empty(),
            "no relay status at all: the relays were never reached, so nothing refused anything"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.to_lowercase().contains("auth")),
            "the relays failed for some reason other than refusing the token: {errors:?}"
        );
    }
}
