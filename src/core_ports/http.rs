use dybw_core::ports::{Http, HttpRequest, HttpResponse, Method, PortError};
use std::time::Duration;
use zeroize::Zeroizing;

pub struct HttpPort {
    client: reqwest::Client,
}

impl HttpPort {
    pub fn new() -> Result<Self, PortError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            // A redirect could carry the API key to another host.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("bwss/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| PortError(format!("http client: {e}")))?;
        Ok(HttpPort { client })
    }
}

fn net(e: reqwest::Error) -> PortError {
    PortError(format!("network: {}", e.without_url()))
}

impl Http for HttpPort {
    fn refuses_redirects(&self) -> bool {
        true
    }

    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, PortError> {
        let mut r = self.client.request(
            match req.method {
                Method::Get => reqwest::Method::GET,
                Method::Post => reqwest::Method::POST,
                Method::Put => reqwest::Method::PUT,
            },
            &req.url,
        );
        for (k, v) in &req.headers {
            r = r.header(k, v);
        }
        if let Some(body) = &req.body {
            r = r.body(body.to_vec());
        }
        let mut res = r.send().await.map_err(net)?;
        let status = res.status();
        if status.is_redirection() {
            return Err(PortError(format!("the server answered with a redirect ({})", status.as_u16())));
        }
        let limit = req.max_body;
        let too_large = || PortError(format!("the response is larger than {limit} bytes"));
        let announced = res.content_length().map(|n| usize::try_from(n).unwrap_or(usize::MAX));
        if announced.is_some_and(|n| n > limit) {
            return Err(too_large());
        }
        // A lying header must not make us reserve the whole cap.
        let mut body = Zeroizing::new(Vec::with_capacity(announced.unwrap_or(0).min(1024 * 1024)));
        while let Some(chunk) = res.chunk().await.map_err(net)? {
            let need = body.len().saturating_add(chunk.len());
            if need > limit {
                return Err(too_large());
            }
            if need > body.capacity() {
                // Move into a new buffer so the old one is wiped as it drops.
                let mut grown =
                    Zeroizing::new(Vec::with_capacity(body.capacity().saturating_mul(2).min(limit).max(need)));
                grown.extend_from_slice(&body);
                body = grown;
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpResponse { status: status.as_u16(), body })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serves `canned` to one connection; returns the base URL.
    async fn serve_once(canned: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/x", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(&canned).await;
            let _ = s.shutdown().await;
        });
        url
    }

    fn get(url: String, max_body: usize) -> HttpRequest {
        HttpRequest { method: Method::Get, url, headers: vec![("X-T".into(), "1".into())], body: None, max_body }
    }

    #[tokio::test]
    async fn http_refuses_a_redirect() {
        let url =
            serve_once(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n".to_vec())
                .await;
        let http = HttpPort::new().unwrap();
        assert!(http.refuses_redirects());
        let err = http.send(get(url, 1024)).await.err().unwrap();
        assert!(err.0.contains("redirect (302)"), "{err}");
    }

    #[tokio::test]
    async fn http_stops_at_max_body() {
        let http = HttpPort::new().unwrap();
        // Announced length over the cap.
        let url = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789".to_vec()).await;
        assert!(http.send(get(url, 5)).await.is_err());
        // No announced length (read until close): caught while streaming.
        let url = serve_once(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n0123456789".to_vec()).await;
        assert!(http.send(get(url, 5)).await.is_err());
        // Within the cap, with a request body and a non-GET method.
        let url = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n01234".to_vec()).await;
        let mut req = get(url, 5);
        req.method = Method::Post;
        req.body = Some(Zeroizing::new(b"b".to_vec()));
        let res = http.send(req).await.unwrap();
        assert_eq!((res.status, res.body.as_slice()), (200, &b"01234"[..]));
    }

    #[tokio::test]
    async fn http_reports_a_network_error_without_the_url() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/secret-path", l.local_addr().unwrap());
        drop(l);
        let err = HttpPort::new().unwrap().send(get(url, 5)).await.err().unwrap();
        assert!(!err.0.contains("secret-path"), "{err}");
    }

    #[tokio::test]
    async fn http_grows_the_body_across_chunks_and_puts() {
        let big = vec![b'a'; 3 * 1024 * 1024];
        let mut canned = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", big.len()).into_bytes();
        canned.extend_from_slice(&big);
        let url = serve_once(canned).await;
        let mut req = get(url, 4 * 1024 * 1024);
        req.method = Method::Put;
        assert_eq!(HttpPort::new().unwrap().send(req).await.unwrap().body.len(), big.len());
    }
}
