//! Loopback port forwarding — the phone's WebView reaching a server bound to this host's
//! `127.0.0.1`, which is where every dev server the owner starts from an agent session lands.
//!
//! A forward stream carries no framing of its own: two bytes of big-endian port, then the TCP
//! connection's bytes verbatim in both directions, until one end closes. Staying byte-transparent
//! is the whole design. An HTTP-aware proxy would have to grow WebSocket upgrade, chunked
//! transfer, SSE, and keep-alive handling before it could show a Vite page; a byte pipe needs
//! none of them, and hot reload works because nothing here knows it exists.
//!
//! **Trust.** A paired device already holds a PTY on this host, so `curl localhost:5432` is
//! available to it whether or not this module exists. Forwarding a loopback port therefore grants
//! no authority the pairing did not already grant, which is why there is no port allowlist: one
//! would be a UI affordance dressed as a boundary, and the boundary is the pairing.

use std::io;
use std::net::Ipv4Addr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// The port the app named, big-endian. Port 0 means "any port" to `bind` and nothing at all to
/// `connect`, so it is refused here rather than turned into a confusing connect error.
pub async fn read_forward_open<R>(recv: &mut R) -> io::Result<u16>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0_u8; 2];
    recv.read_exact(&mut bytes).await?;
    let port = u16::from_be_bytes(bytes);
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "forward stream named port 0",
        ));
    }
    Ok(port)
}

/// Dial the loopback port this stream names and copy bytes both ways until both halves end.
///
/// Generic over the stream halves so the tests below can drive the whole path over an in-memory
/// duplex; in the daemon these are the QUIC stream's own halves.
pub async fn forward<S, R>(send: &mut S, recv: &mut R) -> io::Result<()>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    let port = read_forward_open(recv).await?;
    let upstream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    // Every byte here has already paid a relay round trip. Nagle would add another one to each
    // small write, and there is no bandwidth on this path worth buying with it.
    upstream.set_nodelay(true)?;
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    // The two directions close independently. A browser that has finished sending its request
    // body is still waiting for the response, so EOF one way must forward a half-close rather
    // than tear the whole stream down.
    let to_upstream = async {
        tokio::io::copy(recv, &mut upstream_write).await?;
        upstream_write.shutdown().await
    };
    let to_app = async {
        tokio::io::copy(&mut upstream_read, send).await?;
        send.shutdown().await
    };
    tokio::try_join!(to_upstream, to_app)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::net::TcpListener;

    /// One pass over the whole contract: the two preface bytes select a real loopback listener,
    /// request bytes arrive upstream unchanged, and the reply comes back the same way.
    #[tokio::test]
    async fn forwarded_bytes_reach_the_named_loopback_port_and_come_back() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 5];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping\n");
            socket.write_all(b"pong\n").await.unwrap();
        });

        let (mut app_write, mut host_recv) = duplex(64 * 1024);
        let (mut host_send, mut app_read) = duplex(64 * 1024);
        let forwarding = tokio::spawn(async move { forward(&mut host_send, &mut host_recv).await });

        app_write.write_all(&port.to_be_bytes()).await.unwrap();
        app_write.write_all(b"ping\n").await.unwrap();
        let mut reply = [0_u8; 5];
        app_read.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong\n");

        app_write.shutdown().await.unwrap();
        upstream.await.unwrap();
        forwarding.await.unwrap().unwrap();
    }

    /// Nothing listening must fail the stream, which is what closes the app's local socket and
    /// gets the browser its own error page. Hanging instead would read as a tab that loads
    /// forever with nothing to say about it.
    #[tokio::test]
    async fn a_port_with_nothing_listening_fails_the_stream() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (mut app_write, mut host_recv) = duplex(64);
        let (mut host_send, _app_read) = duplex(64);
        app_write.write_all(&port.to_be_bytes()).await.unwrap();

        assert!(forward(&mut host_send, &mut host_recv).await.is_err());
    }

    #[tokio::test]
    async fn port_zero_is_refused_before_any_dial() {
        let (mut app_write, mut host_recv) = duplex(64);
        let (mut host_send, _app_read) = duplex(64);
        app_write.write_all(&0_u16.to_be_bytes()).await.unwrap();

        let error = forward(&mut host_send, &mut host_recv).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
