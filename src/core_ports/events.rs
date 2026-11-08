use dybw_core::ports::{EventSocket, Events, Frame, PortError};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// The hub sends small notifications; the core refuses anything over 1 MiB too.
const MAX_MESSAGE: usize = 1 << 20;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The notifications hub over a WebSocket (rustls, the system's roots). The
/// client never follows a redirect: any answer but `101` fails the connect.
/// The URL carries the access token, so no error here ever includes it.
pub struct WsEvents;

pub struct WsSocket(WebSocketStream<MaybeTlsStream<TcpStream>>);

fn failed(e: impl std::fmt::Display) -> PortError {
    PortError(format!("notifications: {e}"))
}

impl Events for WsEvents {
    type Socket = WsSocket;

    async fn connect(&self, url: &str) -> Result<WsSocket, PortError> {
        let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
        let connecting = tokio_tungstenite::connect_async_tls_with_config(url, Some(config), true, None);
        match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
            Ok(Ok((socket, _))) => Ok(WsSocket(socket)),
            Ok(Err(e)) => Err(failed(e)),
            Err(_) => Err(failed("the connection timed out")),
        }
    }
}

impl EventSocket for WsSocket {
    async fn send(&mut self, frame: Frame) -> Result<(), PortError> {
        let message = match frame {
            Frame::Text(t) => Message::text(t),
            Frame::Binary(b) => Message::binary(b),
        };
        self.0.send(message).await.map_err(failed)
    }

    /// Cancel-safe: `next` keeps a partly read frame in the stream.
    async fn recv(&mut self) -> Option<Result<Frame, PortError>> {
        loop {
            return match self.0.next().await? {
                Ok(Message::Text(t)) => Some(Ok(Frame::Text(t.as_str().to_owned()))),
                Ok(Message::Binary(b)) => Some(Ok(Frame::Binary(b.to_vec()))),
                Ok(Message::Close(_)) => None,
                // Pings are answered by tungstenite itself.
                Ok(_) => continue,
                Err(e) => Some(Err(failed(e))),
            };
        }
    }

    async fn close(&mut self) {
        let _ = self.0.close(None).await;
    }
}

/// A notifications hub on loopback, for tests.
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
pub(crate) mod test_hub {
    use super::*;
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    /// What the hub saw.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum Seen {
        /// A client connected, asking for this path and query.
        Open(String),
        /// That client went away.
        Closed,
    }

    /// One SignalR `ReceiveMessage` invocation with a cipher change from
    /// device `context`, as a MessagePack frame with its length prefix.
    pub(crate) fn change_from(context: &str) -> Vec<u8> {
        let mut m = vec![0x95, 0x01, 0x80, 0xc0, 0xae];
        m.extend_from_slice(b"ReceiveMessage");
        m.extend_from_slice(&[0x91, 0x82, 0xa9]);
        m.extend_from_slice(b"ContextId");
        m.push(0xa0 | u8::try_from(context.len()).unwrap());
        m.extend_from_slice(context.as_bytes());
        m.push(0xa4);
        m.extend_from_slice(b"Type");
        m.push(0x00);
        let mut framed = vec![u8::try_from(m.len()).unwrap()];
        framed.extend(m);
        framed
    }

    /// Serves every connection: answers the handshake, sends `burst` change
    /// notifications from another device, then holds the connection until
    /// the client goes. Returns the hub's base URL (as `ServerUrls.notifications`).
    pub(crate) async fn serve(burst: usize) -> (String, mpsc::UnboundedReceiver<Seen>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (seen, events) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    let opened = seen.clone();
                    #[expect(clippy::result_large_err, reason = "the callback type is tungstenite's")]
                    let callback = move |req: &Request, res: Response| {
                        let _ = opened.send(Seen::Open(req.uri().to_string()));
                        Ok(res)
                    };
                    // The client may go at any step: every way out reports it.
                    let session = async {
                        let mut ws = tokio_tungstenite::accept_hdr_async(tcp, callback).await.ok()?;
                        // The client's handshake, then the server's answer.
                        ws.next().await?.ok()?;
                        ws.send(Message::text("{}\u{1e}")).await.ok()?;
                        for _ in 0..burst {
                            ws.send(Message::binary(change_from("another-device"))).await.ok()?;
                        }
                        while let Some(Ok(_)) = ws.next().await {}
                        Some(())
                    };
                    session.await;
                    let _ = seen.send(Seen::Closed);
                });
            }
        });
        (base, events)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn the_socket_passes_frames_skips_pings_and_ends_on_close() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/hub", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut ws = tokio_tungstenite::accept_async(listener.accept().await.unwrap().0).await.unwrap();
            let got = ws.next().await.unwrap().unwrap();
            ws.send(Message::Ping(vec![1].into())).await.unwrap();
            ws.send(Message::text("t")).await.unwrap();
            ws.send(Message::binary(vec![2, 3])).await.unwrap();
            ws.close(None).await.unwrap();
            got
        });
        let mut socket = WsEvents.connect(&url).await.unwrap();
        socket.send(Frame::Text("hello".into())).await.unwrap();
        assert_eq!(socket.recv().await.unwrap().unwrap(), Frame::Text("t".into()));
        assert_eq!(socket.recv().await.unwrap().unwrap(), Frame::Binary(vec![2, 3]));
        assert!(socket.recv().await.is_none(), "a close frame ends the socket");
        assert_eq!(server.await.unwrap(), Message::text("hello"));
        socket.close().await;
        assert!(socket.send(Frame::Binary(vec![1])).await.is_err(), "closed");
    }

    #[tokio::test]
    async fn a_dropped_connection_is_an_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/hub", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let ws = tokio_tungstenite::accept_async(listener.accept().await.unwrap().0).await.unwrap();
            drop(ws); // no closing handshake
        });
        let mut socket = WsEvents.connect(&url).await.unwrap();
        assert!(socket.recv().await.unwrap().is_err());
    }

    #[tokio::test]
    async fn a_redirect_is_refused_and_the_error_holds_no_token() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/hub?access_token=SECRET-TOKEN", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            let _ =
                s.write_all(b"HTTP/1.1 302 Found\r\nLocation: ws://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n").await;
        });
        let err = WsEvents.connect(&url).await.err().unwrap();
        assert!(err.0.contains("302"), "{err}");
        assert!(!err.0.contains("SECRET-TOKEN"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_that_never_answers_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/hub", listener.local_addr().unwrap());
        let err = WsEvents.connect(&url).await.err().unwrap();
        assert!(err.0.contains("timed out"), "{err}");
        drop(listener);
    }
}
