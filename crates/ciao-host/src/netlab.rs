//! The network lab's headless phone.
//!
//! Dials a lab daemon the way the app does — paired identity, `host.hello`, one terminal —
//! and then narrates what the transport sees once a second: the selected path, and per path
//! the rtt, datagrams in and out, ACK frames received, and packets lost. It exists so a
//! blackhole can be dialled in from *inside a Lima VM* with iptables (no root on the Mac),
//! which is the one scenario the simulator lab could never produce: a path that dies under
//! a live connection while the relay stays reachable (Spec 014 Class B). Env-gated and
//! `#[ignore]`d like the relay probes in `relay.rs`; `scripts/netlab_blackhole.sh` drives it.
//!
//! Lab output only — this test prints the remote address of a direct path so the driver can
//! write the iptables rule that kills it. Nothing here runs in the product.
//!
//! ```sh
//! CIAO_NETLAB_PHONE_SECRET=<64 hex> cargo test -p ciao-host netlab_phone_identity -- --ignored --nocapture
//! CIAO_NETLAB_HOST_ID=<hex> CIAO_NETLAB_PHONE_SECRET=<64 hex> CIAO_NETLAB_SECONDS=90 \
//!   ./ciao_host-<hash> netlab_phone_holds_a_terminal -- --ignored --nocapture
//! ```

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use iroh::{
        EndpointAddr, EndpointId, RelayUrl, SecretKey,
        endpoint::{Connection, Endpoint, presets},
    };

    use crate::host_protocol::{
        Dimensions, HOST_ALPN, HostHelloParams, HostHelloRequest, RpcResponse, StreamKind,
        TerminalFrame, TerminalFrameReader, TerminalOpen, decode_rpc_response, read_rpc_body,
        read_terminal_frame, write_rpc, write_stream_preface, write_terminal_frame,
    };

    fn env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|value| !value.is_empty())
    }

    fn phone_secret() -> SecretKey {
        let hex = env("CIAO_NETLAB_PHONE_SECRET").expect("CIAO_NETLAB_PHONE_SECRET (64 hex)");
        let bytes = hex_bytes(&hex);
        SecretKey::from_bytes(&bytes.try_into().expect("32-byte secret"))
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// Prints the endpoint id the lab daemon must list in `paired-devices.json` before the
    /// phone dials. Run natively; the id only depends on the secret.
    #[tokio::test]
    #[ignore = "prints the lab phone's identity; needs CIAO_NETLAB_PHONE_SECRET"]
    async fn netlab_phone_identity() {
        println!("phone id {}", phone_secret().public());
    }

    struct PathRow {
        id: String,
        kind: &'static str,
        selected: bool,
        rtt_ms: u128,
        rx: u64,
        tx: u64,
        acks: u64,
        lost: u64,
        remote: String,
    }

    fn path_rows(connection: &Connection) -> Vec<PathRow> {
        connection
            .paths()
            .iter()
            .map(|path| {
                let stats = path.stats();
                PathRow {
                    id: format!("{:?}", path.id()),
                    kind: if path.is_relay() {
                        "relay"
                    } else if path.is_ip() {
                        "ip"
                    } else {
                        "other"
                    },
                    selected: path.is_selected(),
                    rtt_ms: stats.rtt.as_millis(),
                    rx: stats.udp_rx.datagrams,
                    tx: stats.udp_tx.datagrams,
                    acks: stats.frame_rx.acks,
                    lost: stats.lost_packets,
                    remote: format!("{}", path.remote_addr()),
                }
            })
            .collect()
    }

    fn selected_kind(rows: &[PathRow]) -> &'static str {
        rows.iter()
            .find(|row| row.selected)
            .map(|row| row.kind)
            .unwrap_or("none")
    }

    async fn dial(endpoint: &Endpoint, addr: EndpointAddr) -> anyhow::Result<Connection> {
        let connection = endpoint.connect(addr, HOST_ALPN).await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        write_stream_preface(&mut send, StreamKind::Rpc).await?;
        write_rpc(
            &mut send,
            &HostHelloRequest {
                v: 1,
                message_type: "request".into(),
                request_id: "AAECAwQFBgcICQoLDA0ODw".into(),
                method: "host.hello".into(),
                params: HostHelloParams {
                    min_protocol: 1,
                    max_protocol: 1,
                },
            },
        )
        .await?;
        send.finish()?;
        let body = read_rpc_body(&mut recv).await?;
        match decode_rpc_response(&body)? {
            RpcResponse::Hello(_) => Ok(connection),
            other => anyhow::bail!("hello answered with {other:?}"),
        }
    }

    /// One attached terminal, narrated until the deadline or until the connection dies.
    /// Returns why it stopped.
    async fn hold_terminal(
        connection: &Connection,
        session: &str,
        deadline: Instant,
        began: Instant,
    ) -> String {
        let (mut send, mut recv) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(error) => return format!("open_bi {error}"),
        };
        if let Err(error) = write_stream_preface(&mut send, StreamKind::Terminal).await {
            return format!("preface {error}");
        }
        let open_began = Instant::now();
        let target = if session.is_empty() {
            "shell"
        } else {
            "tmux.attach"
        };
        let open = TerminalOpen {
            v: 1,
            target: target.into(),
            session: (!session.is_empty()).then(|| session.to_string()),
            tab: None,
            dimensions: Dimensions {
                cols: 100,
                rows: 30,
                pixel_width: 0,
                pixel_height: 0,
            },
        };
        if let Err(error) = write_terminal_frame(&mut send, &TerminalFrame::Open(open)).await {
            return format!("open {error}");
        }
        match read_terminal_frame(&mut recv).await {
            Ok(TerminalFrame::Opened(_)) => println!(
                "t={:.3} terminal opened {}ms",
                began.elapsed().as_secs_f64(),
                open_began.elapsed().as_millis()
            ),
            Ok(other) => return format!("open answered {other:?}"),
            Err(error) => return format!("opened {error}"),
        }

        let mut frames = TerminalFrameReader::default();
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_output = Instant::now();
        let mut out_since_tick: u64 = 0;
        let mut in_gap = false;
        let mut previous: Vec<PathRow> = Vec::new();
        let mut last_selected = selected_kind(&path_rows(connection));
        loop {
            tokio::select! {
                frame = frames.next(&mut recv) => match frame {
                    Ok(TerminalFrame::Output(bytes)) => {
                        let gap = last_output.elapsed();
                        if in_gap {
                            println!(
                                "t={:.3} output resumed after {}ms",
                                began.elapsed().as_secs_f64(),
                                gap.as_millis()
                            );
                            in_gap = false;
                        }
                        out_since_tick += bytes.len() as u64;
                        last_output = Instant::now();
                    }
                    Ok(TerminalFrame::Exit(exit)) => return format!("exit {}", exit.kind),
                    Ok(TerminalFrame::Error(error)) => return format!("error {}", error.code),
                    Ok(other) => return format!("unexpected {other:?}"),
                    Err(error) => return format!("read {error}"),
                },
                _ = ticker.tick() => {
                    let rows = path_rows(connection);
                    let selected = selected_kind(&rows);
                    if selected != last_selected {
                        println!(
                            "t={:.3} path {} -> {}",
                            began.elapsed().as_secs_f64(),
                            last_selected,
                            selected
                        );
                        last_selected = selected;
                    }
                    let gap_ms = last_output.elapsed().as_millis();
                    if gap_ms >= 2000 { in_gap = true; }
                    let rtt = rows
                        .iter()
                        .find(|row| row.selected)
                        .map(|row| row.rtt_ms.to_string())
                        .unwrap_or_else(|| "-".into());
                    let detail = rows
                        .iter()
                        .map(|row| {
                            let prev = previous.iter().find(|p| p.id == row.id);
                            let delta = |now: u64, then: Option<u64>| now.saturating_sub(then.unwrap_or(0));
                            format!(
                                "[{}:{}:{}:rtt={}:rx+{}:tx+{}:acks+{}:lost+{}:{}]",
                                row.id,
                                row.kind,
                                if row.selected { "sel" } else { "-" },
                                row.rtt_ms,
                                delta(row.rx, prev.map(|p| p.rx)),
                                delta(row.tx, prev.map(|p| p.tx)),
                                delta(row.acks, prev.map(|p| p.acks)),
                                delta(row.lost, prev.map(|p| p.lost)),
                                row.remote,
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" ");
                    println!(
                        "t={:.3} sel={} rtt={} out+{} gap={} paths={} {}",
                        began.elapsed().as_secs_f64(),
                        selected,
                        rtt,
                        out_since_tick,
                        gap_ms,
                        rows.len(),
                        detail
                    );
                    out_since_tick = 0;
                    previous = rows;
                    if Instant::now() >= deadline {
                        let _ = write_terminal_frame(&mut send, &TerminalFrame::Close).await;
                        return "deadline".into();
                    }
                }
                error = connection.closed() => return format!("closed {error}"),
            }
        }
    }

    #[tokio::test]
    #[ignore = "dials a lab daemon; needs CIAO_NETLAB_HOST_ID and CIAO_NETLAB_PHONE_SECRET"]
    async fn netlab_phone_holds_a_terminal_and_narrates_its_paths() {
        let host_id: EndpointId = env("CIAO_NETLAB_HOST_ID")
            .expect("CIAO_NETLAB_HOST_ID")
            .parse()
            .expect("host endpoint id");
        let seconds: u64 = env("CIAO_NETLAB_SECONDS")
            .and_then(|value| value.parse().ok())
            .unwrap_or(120);
        let session = env("CIAO_NETLAB_SESSION").unwrap_or_else(|| "lab".into());
        let relay_url: RelayUrl = env("CIAO_NETLAB_RELAY_URL")
            .unwrap_or_else(|| crate::relay::RELAY_URLS[0].to_string())
            .parse()
            .expect("relay url");

        let mut builder = Endpoint::builder(presets::N0).secret_key(phone_secret());
        if let Some(map) = crate::relay::configured_map().expect("relay map") {
            builder = builder.relay_mode(iroh::endpoint::RelayMode::Custom(map));
        }
        let began = Instant::now();
        let endpoint = builder.bind().await.expect("bind the lab phone");
        endpoint.online().await;
        println!(
            "t={:.3} online id={}",
            began.elapsed().as_secs_f64(),
            endpoint.id()
        );
        let deadline = began + Duration::from_secs(seconds);

        while Instant::now() < deadline {
            let dial_began = Instant::now();
            let addr = EndpointAddr::new(host_id).with_relay_url(relay_url.clone());
            let connection =
                match tokio::time::timeout(Duration::from_secs(10), dial(&endpoint, addr)).await {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(error)) => {
                        println!(
                            "t={:.3} dial fail {}ms {error}",
                            began.elapsed().as_secs_f64(),
                            dial_began.elapsed().as_millis()
                        );
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                    Err(_) => {
                        println!(
                            "t={:.3} dial timeout {}ms",
                            began.elapsed().as_secs_f64(),
                            dial_began.elapsed().as_millis()
                        );
                        continue;
                    }
                };
            println!(
                "t={:.3} dial ok {}ms sel={}",
                began.elapsed().as_secs_f64(),
                dial_began.elapsed().as_millis(),
                selected_kind(&path_rows(&connection))
            );
            let why = hold_terminal(&connection, &session, deadline, began).await;
            println!(
                "t={:.3} terminal ended {why}",
                began.elapsed().as_secs_f64()
            );
            connection.close(0u32.into(), b"lab phone done");
            if why == "deadline" {
                break;
            }
        }
        endpoint.close().await;
        println!("t={:.3} exit", began.elapsed().as_secs_f64());
    }
}
