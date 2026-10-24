//! Minimal Bitwarden REST client: prelogin, API-key login, sync, folders and
//! item writes. Items are kept as JSON values so that edits pass every field
//! this client does not model straight back to the server.

use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use url::Url;
use zeroize::Zeroizing;

use super::crypto::KdfParams;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("network error: {0}")]
    Network(String),
    #[error("HTTP {status}{}", if .message.is_empty() { String::new() } else { format!(" (server says: {})", .message) })]
    Http { status: u16, message: String },
    #[error("unexpected response: {0}")]
    Protocol(String),
    /// A write before this session's first `/sync` (for example right
    /// after a logout and a new login): it can be sent after the next sync.
    #[error("sync before writing items")]
    NotSynced,
}

impl ApiError {
    /// The server rejected an edit because the item changed elsewhere.
    pub fn is_out_of_date(&self) -> bool {
        matches!(self, ApiError::Http { status: 400, message } if message.to_lowercase().contains("out of date"))
    }

    /// Failures that mean "try again later" rather than "this request is wrong".
    pub fn is_transient(&self) -> bool {
        match self {
            ApiError::Network(_) => true,
            ApiError::Http { status, .. } => *status == 429 || *status >= 500,
            ApiError::NotSynced => true,
            ApiError::Protocol(_) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrls {
    pub api: String,
    pub identity: String,
}

/// Maps a vault URL to the API and identity endpoints.
pub fn resolve_server_urls(server_url: &str) -> Result<ServerUrls, String> {
    let raw = if server_url.trim().is_empty() { "https://vault.bitwarden.com" } else { server_url.trim() };
    let url = Url::parse(raw).map_err(|e| format!("invalid server URL {raw:?}: {e}"))?;
    let host = url.host_str().unwrap_or_default();
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1");
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err("the server URL must use https:// (plain http is only allowed for localhost)".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("the server URL must not contain credentials".into());
    }
    Ok(match host {
        "vault.bitwarden.com" | "bitwarden.com" => {
            ServerUrls { api: "https://api.bitwarden.com".into(), identity: "https://identity.bitwarden.com".into() }
        }
        "vault.bitwarden.eu" | "bitwarden.eu" => {
            ServerUrls { api: "https://api.bitwarden.eu".into(), identity: "https://identity.bitwarden.eu".into() }
        }
        _ => {
            let base = format!("{}{}", url.origin().ascii_serialization(), url.path()).trim_end_matches('/').to_owned();
            ServerUrls { api: format!("{base}/api"), identity: format!("{base}/identity") }
        }
    })
}

/// Bitwarden used to answer in PascalCase; newer servers use camelCase.
pub fn normalize_keys(value: Value) -> Value {
    match value {
        Value::Array(a) => Value::Array(a.into_iter().map(normalize_keys).collect()),
        Value::Object(o) => Value::Object(
            o.into_iter()
                .map(|(k, v)| {
                    let mut c = k.chars();
                    let key = match c.next() {
                        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
                        None => k,
                    };
                    (key, normalize_keys(v))
                })
                .collect(),
        ),
        v => v,
    }
}

/// `scheme://host[:port]` of `url`, the unit an API key is bound to.
pub fn origin_of(url: &str) -> Result<String, String> {
    Url::parse(url).map(|u| u.origin().ascii_serialization()).map_err(|e| format!("invalid URL {url:?}: {e}"))
}

/// The identity origin of a vault URL: where its API key may go.
pub fn identity_origin(server_url: &str) -> Result<String, String> {
    origin_of(&resolve_server_urls(server_url)?.identity)
}

#[derive(Clone)]
pub struct ApiKey {
    /// The only identity origin this key may be sent to.
    pub origin: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("origin", &self.origin)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

// DeviceType.LinuxDesktop in the Bitwarden server enum.
const DEVICE_TYPE: &str = "8";
const CLIENT_NAME: &str = "bwss";

fn build_client(builder: reqwest::ClientBuilder) -> Result<reqwest::Client, ApiError> {
    builder.build().map_err(|e| ApiError::Network(e.to_string()))
}

pub struct Api {
    urls: ServerUrls,
    http: reqwest::Client,
    device_id: String,
    token: Option<(Zeroizing<String>, Instant)>,
    user_id: Option<String>,
    /// Largest response body read (`MAX_BODY`; tests lower it).
    body_limit: usize,
}

/// Largest response body bwss reads, enforced while it streams in.
pub const MAX_BODY: usize = 256 * 1024 * 1024;

impl Api {
    pub fn new(urls: ServerUrls, device_id: String) -> Result<Self, ApiError> {
        let builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            // A redirect could carry the API key to another host.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("bwss/", env!("CARGO_PKG_VERSION")));
        let http = build_client(builder)?;
        Ok(Api { urls, http, device_id, token: None, user_id: None, body_limit: MAX_BODY })
    }

    pub fn urls(&self) -> &ServerUrls {
        &self.urls
    }

    /// Sends a request and returns the body text of a 2xx answer.
    ///
    /// The body is wrapped in `Zeroizing` at once because the login answer
    /// carries the access token.
    async fn send_text(&self, req: reqwest::RequestBuilder) -> Result<Zeroizing<String>, ApiError> {
        let res = req
            .header("Bitwarden-Client-Name", CLIENT_NAME)
            .header("Bitwarden-Client-Version", env!("CARGO_PKG_VERSION"))
            .header("Device-Type", DEVICE_TYPE)
            .send()
            .await
            .map_err(|e| ApiError::Network(e.without_url().to_string()))?;
        let status = res.status().as_u16();
        let text = read_capped(res, self.body_limit).await?;
        if !(200..300).contains(&status) {
            return Err(ApiError::Http { status, message: describe_error(&parse_body(&text)) });
        }
        Ok(text)
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Value, ApiError> {
        self.send_text(req).await.map(|text| parse_body(&text))
    }

    pub async fn prelogin(&self, email: &str) -> Result<KdfParams, ApiError> {
        let body = self
            .send(self.http.post(format!("{}/accounts/prelogin", self.urls.identity)).json(&json!({ "email": email })))
            .await?;
        let num = |k: &str| body.get(k).and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok());
        match num("kdf") {
            Some(0) => Ok(KdfParams::Pbkdf2 { iterations: num("kdfIterations").unwrap_or(0) }),
            Some(1) => Ok(KdfParams::Argon2id {
                iterations: num("kdfIterations").unwrap_or(0),
                memory_mib: num("kdfMemory").unwrap_or(0),
                parallelism: num("kdfParallelism").unwrap_or(0),
            }),
            other => Err(ApiError::Protocol(format!("unsupported KDF type {other:?}"))),
        }
    }

    /// Logs in with a personal API key. It authenticates only; decrypting
    /// still needs the master password.
    ///
    /// Known limitation: reqwest copies the client secret (form body) and
    /// the access token (Authorization header) into its own buffers, which
    /// bwss cannot wipe.
    pub async fn login(&mut self, key: &ApiKey) -> Result<(), ApiError> {
        // The key is bound to the identity origin it was entered for (TM-007).
        let here = origin_of(&self.urls.identity).map_err(ApiError::Protocol)?;
        if key.origin != here {
            return Err(ApiError::Protocol(format!(
                "the API key was saved for {}, not {here}; run `bwss login` again",
                key.origin
            )));
        }
        let form = [
            ("grant_type", "client_credentials"),
            ("scope", "api"),
            ("client_id", key.client_id.as_str()),
            ("client_secret", key.client_secret.as_str()),
            ("deviceType", DEVICE_TYPE),
            ("deviceIdentifier", self.device_id.as_str()),
            ("deviceName", "bwss"),
        ];
        let text = self.send_text(self.http.post(format!("{}/connect/token", self.urls.identity)).form(&form)).await?;
        let (token, ttl) = parse_token_response(&text)?;
        self.token = Some((token, Instant::now() + Duration::from_secs(ttl)));
        Ok(())
    }

    pub fn is_logged_in(&self) -> bool {
        self.token.as_ref().is_some_and(|(_, exp)| *exp > Instant::now())
    }

    /// Whether a `/sync` has run since login, so item writes can name
    /// their owner.
    pub fn has_profile(&self) -> bool {
        self.user_id.is_some()
    }

    pub fn logout(&mut self) {
        self.token = None;
        self.user_id = None;
    }

    fn authed(&self, req: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder, ApiError> {
        match &self.token {
            Some((t, exp)) if *exp > Instant::now() => Ok(req.bearer_auth(t.as_str())),
            _ => Err(ApiError::Http { status: 401, message: "not logged in".into() }),
        }
    }

    pub async fn sync(&mut self) -> Result<Value, ApiError> {
        let req = self.authed(self.http.get(format!("{}/sync?excludeDomains=true", self.urls.api)))?;
        let body = self.send(req).await?;
        let id = body
            .pointer("/profile/id")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::Protocol("sync response has no profile".into()))?;
        self.user_id = Some(id.to_owned());
        Ok(body)
    }

    /// The account's revision date as the server sends it (a JSON number of
    /// milliseconds, or a string), kept as raw text: it is only compared.
    pub async fn revision_date(&self) -> Result<String, ApiError> {
        let req = self.authed(self.http.get(format!("{}/accounts/revision-date", self.urls.api)))?;
        Ok(self.send_text(req).await?.trim().to_owned())
    }

    /// One cipher, fresh from the server.
    pub async fn get_item(&self, id: &str) -> Result<Value, ApiError> {
        let req = self.authed(self.http.get(format!("{}/ciphers/{}", self.urls.api, enc(id))))?;
        self.send(req).await
    }

    pub async fn create_folder(&self, encrypted_name: &str) -> Result<Value, ApiError> {
        let req = self.authed(self.http.post(format!("{}/folders", self.urls.api)))?;
        self.send(req.json(&json!({ "name": encrypted_name }))).await
    }

    fn with_owner(&self, mut body: Map<String, Value>) -> Result<Value, ApiError> {
        // Required by Vaultwarden 1.37+, optional on bitwarden.com.
        let owner = self.user_id.clone().ok_or(ApiError::NotSynced)?;
        body.insert("encryptedFor".into(), Value::String(owner));
        Ok(Value::Object(body))
    }

    pub async fn create_item(&self, body: Map<String, Value>) -> Result<Value, ApiError> {
        let req = self.authed(self.http.post(format!("{}/ciphers", self.urls.api)))?;
        self.send(req.json(&self.with_owner(body)?)).await
    }

    pub async fn update_item(&self, id: &str, body: Map<String, Value>) -> Result<Value, ApiError> {
        let req = self.authed(self.http.put(format!("{}/ciphers/{}", self.urls.api, enc(id))))?;
        self.send(req.json(&self.with_owner(body)?)).await
    }

    /// Moves the item to the trash, where any Bitwarden client can restore it.
    pub async fn trash_item(&self, id: &str) -> Result<(), ApiError> {
        let req = self.authed(self.http.put(format!("{}/ciphers/{}/delete", self.urls.api, enc(id))))?;
        self.send(req).await.map(|_| ())
    }
}

/// What is reserved before the body arrives: the announced length, but at
/// most 1 MiB, so a lying header cannot make bwss allocate the whole cap.
fn initial_capacity(announced: Option<usize>) -> usize {
    announced.unwrap_or(0).min(1024 * 1024)
}

/// The capacity to grow to when `need` bytes no longer fit in `capacity`:
/// double, but never past `limit` (`need` is within it).
fn grown_capacity(capacity: usize, need: usize, limit: usize) -> usize {
    capacity.saturating_mul(2).min(limit).max(need)
}

/// Appends `chunk`. When the buffer must grow, the bytes move into a new
/// buffer and the old one is wiped as it drops, so a reallocation never
/// leaves an unwiped copy of the body behind.
fn append_wiped(body: &mut Zeroizing<Vec<u8>>, chunk: &[u8], limit: usize) {
    let need = body.len().saturating_add(chunk.len());
    if need > body.capacity() {
        let mut grown = Zeroizing::new(Vec::with_capacity(grown_capacity(body.capacity(), need, limit)));
        grown.extend_from_slice(body);
        *body = grown;
    }
    body.extend_from_slice(chunk);
}

/// The body of `res` as text, refused as soon as it is known to exceed
/// `limit` bytes: from its announced length, or while the chunks arrive.
async fn read_capped(mut res: reqwest::Response, limit: usize) -> Result<Zeroizing<String>, ApiError> {
    let too_large = || ApiError::Protocol(format!("the response is larger than {limit} bytes"));
    let announced = res.content_length().map(|n| usize::try_from(n).unwrap_or(usize::MAX));
    if announced.is_some_and(|n| n > limit) {
        return Err(too_large());
    }
    let mut body = Zeroizing::new(Vec::with_capacity(initial_capacity(announced)));
    while let Some(chunk) = res.chunk().await.map_err(|e| ApiError::Network(e.without_url().to_string()))? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(too_large());
        }
        append_wiped(&mut body, &chunk, limit);
    }
    Ok(match String::from_utf8(std::mem::take(&mut *body)) {
        Ok(text) => Zeroizing::new(text),
        Err(e) => {
            let bytes = Zeroizing::new(e.into_bytes());
            Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned())
        }
    })
}

/// Reads the token answer straight into wiped storage; returns the token
/// and the seconds it stays usable (with a safety margin).
fn parse_token_response(text: &str) -> Result<(Zeroizing<String>, u64), ApiError> {
    #[derive(serde::Deserialize)]
    struct TokenResponse {
        access_token: Zeroizing<String>,
        expires_in: Option<u64>,
    }
    let r: TokenResponse = serde_json::from_str(text).map_err(|_| ApiError::Protocol("no access token".into()))?;
    Ok((r.access_token, r.expires_in.unwrap_or(3600).saturating_sub(60).max(60)))
}

fn parse_body(text: &str) -> Value {
    if text.is_empty() { Value::Null } else { serde_json::from_str(text).map(normalize_keys).unwrap_or(Value::Null) }
}

fn enc(segment: &str) -> String {
    url::form_urlencoded::byte_serialize(segment.as_bytes()).collect()
}

/// `text` without control characters: ANSI escape sequences (CSI, OSC and
/// the other string controls, two-byte escapes) are dropped whole, every
/// other C0 or C1 control and the line separators become a space, and
/// invisible format characters (`prompter::is_invisible`) are dropped.
fn strip_controls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    // Skips a control string up to BEL or ST (`ESC \`, or C1 U+009C).
    let skip_string = |chars: &mut std::iter::Peekable<std::str::Chars<'_>>| {
        while let Some(c) = chars.next() {
            match c {
                '\u{7}' | '\u{9c}' => return,
                '\u{1b}' if chars.peek() == Some(&'\\') => {
                    chars.next();
                    return;
                }
                _ => {}
            }
        }
    };
    // Skips a CSI sequence: parameter and intermediate bytes, then the final byte.
    let skip_csi = |chars: &mut std::iter::Peekable<std::str::Chars<'_>>| {
        for c in chars.by_ref() {
            if ('\u{40}'..='\u{7e}').contains(&c) {
                return;
            }
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.peek() {
                Some('[') => {
                    chars.next();
                    skip_csi(&mut chars);
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    chars.next();
                    skip_string(&mut chars);
                }
                // Intermediate bytes, then one final byte (`ESC ( B`), or a
                // final byte alone (`ESC c`).
                Some('\u{20}'..='\u{7e}') => {
                    while chars.next_if(|c| ('\u{20}'..='\u{2f}').contains(c)).is_some() {}
                    chars.next_if(|c| ('\u{30}'..='\u{7e}').contains(c));
                }
                // A lone ESC: only it goes, what follows is text.
                _ => {}
            },
            '\u{9b}' => skip_csi(&mut chars),
            '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => skip_string(&mut chars),
            c if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') => out.push(' '),
            // Zero width, so dropped: bidi overrides cannot reorder the text.
            c if crate::prompter::is_invisible(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// Server text is untrusted: keep it short and free of control characters.
fn describe_error(body: &Value) -> String {
    let mut parts = Vec::new();
    for p in ["/error_description", "/message", "/errorModel/message"] {
        if let Some(s) = body.pointer(p).and_then(Value::as_str) {
            parts.push(s.to_owned());
        }
    }
    if let Some(v) = body.get("validationErrors") {
        parts.push(v.to_string());
    }
    let text = strip_controls(&parts.join(" ")).split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() > 200 { text.chars().take(200).collect::<String>() + "…" } else { text }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn token_response_yields_token_and_ttl() {
        let (t, ttl) = parse_token_response(r#"{"access_token":"tok","expires_in":3600,"x":1}"#).unwrap();
        assert_eq!(t.as_str(), "tok");
        assert_eq!(ttl, 3540);
        let (_, ttl) = parse_token_response(r#"{"access_token":"tok"}"#).unwrap();
        assert_eq!(ttl, 3540);
        let (_, ttl) = parse_token_response(r#"{"access_token":"tok","expires_in":10}"#).unwrap();
        assert_eq!(ttl, 60);
        assert!(matches!(parse_token_response(r#"{"expires_in":1}"#), Err(ApiError::Protocol(_))));
        assert!(matches!(parse_token_response("not json"), Err(ApiError::Protocol(_))));
    }

    #[test]
    fn api_key_debug_is_redacted() {
        let k = ApiKey {
            origin: "https://identity.example.org".into(),
            client_id: "the-id".into(),
            client_secret: Zeroizing::new("hunter2-secret".into()),
        };
        let out = format!("{k:?}");
        assert!(!out.contains("hunter2-secret"));
        assert!(out.contains("<redacted>"));
        assert!(out.contains("the-id"));
    }

    #[test]
    fn server_urls() {
        assert_eq!(resolve_server_urls("").unwrap().api, "https://api.bitwarden.com");
        assert_eq!(
            resolve_server_urls("https://vault.bitwarden.eu").unwrap().identity,
            "https://identity.bitwarden.eu"
        );
        assert_eq!(
            resolve_server_urls("https://bw.example.org/vault/").unwrap().api,
            "https://bw.example.org/vault/api"
        );
        assert_eq!(resolve_server_urls("http://127.0.0.1:8080").unwrap().identity, "http://127.0.0.1:8080/identity");
        assert!(resolve_server_urls("http://bw.example.org").is_err());
        let e = resolve_server_urls("not a url").unwrap_err();
        assert!(e.starts_with("invalid server URL \"not a url\": "), "{e}");
        assert!(resolve_server_urls("https://u:p@bw.example.org").is_err());
    }

    #[test]
    fn origins_are_scheme_host_and_port() {
        assert_eq!(origin_of("https://identity.bitwarden.com").unwrap(), "https://identity.bitwarden.com");
        assert_eq!(origin_of("https://bw.example.org/vault/identity").unwrap(), "https://bw.example.org");
        assert_eq!(origin_of("http://127.0.0.1:80/identity").unwrap(), "http://127.0.0.1");
        assert_eq!(origin_of("http://127.0.0.1:8080/identity").unwrap(), "http://127.0.0.1:8080");
        assert_eq!(origin_of("HTTPS://BW.Example.org:443/x").unwrap(), "https://bw.example.org");
        assert!(origin_of("not a url").is_err());
    }

    #[test]
    fn identity_origins_follow_the_server() {
        assert_eq!(identity_origin("https://vault.bitwarden.com").unwrap(), "https://identity.bitwarden.com");
        assert_eq!(identity_origin("https://vault.bitwarden.eu/").unwrap(), "https://identity.bitwarden.eu");
        assert_eq!(identity_origin("https://bw.example.org:8443/vault").unwrap(), "https://bw.example.org:8443");
        assert!(identity_origin("http://bw.example.org").is_err());
    }

    #[tokio::test]
    async fn the_api_key_is_never_sent_to_another_origin() {
        // Nothing listens on port 1: a refusal that is not a network error
        // was decided before any request went out.
        let mut api = Api::new(resolve_server_urls("http://127.0.0.1:1").unwrap(), "d".into()).unwrap();
        let key = ApiKey {
            origin: "https://identity.bitwarden.com".into(),
            client_id: "id".into(),
            client_secret: Zeroizing::new("secret".into()),
        };
        let e = api.login(&key).await.unwrap_err();
        assert!(
            matches!(&e, ApiError::Protocol(m) if m.contains("https://identity.bitwarden.com")
            && m.contains("http://127.0.0.1:1") && m.contains("bwss login")),
            "{e}"
        );
        assert!(!e.is_transient());

        let bound = ApiKey { origin: "http://127.0.0.1:1".into(), ..key };
        assert!(matches!(api.login(&bound).await.unwrap_err(), ApiError::Network(_)), "the right origin is tried");
    }

    #[test]
    fn server_error_text_loses_control_characters_and_escapes() {
        let body = json!({
            "message": "bad\u{1b}[31mred\u{1b}[0m\nnext\u{7} \u{9b}2Jx \u{1b}]0;title\u{7}end \u{1b}(Bok\u{85}\u{1b}"
        });
        assert_eq!(describe_error(&body), "badred next x end ok");
        // Invisible format characters go too: bidi overrides cannot reorder it.
        let bidi = json!({ "message": "use\u{202e}gnorw\u{202c} \u{200b}x\u{feff}y\u{ad}z\u{2066}!\u{2069}" });
        assert_eq!(describe_error(&bidi), "usegnorw xyz!");
        // A lone ESC goes alone: what follows it is not a sequence.
        let lone = json!({ "message": "a\u{1b}ébc \u{1b}\u{1b}[1mx \u{1b}\nz" });
        assert_eq!(describe_error(&lone), "aébc x z");
        // Control strings end at ST, as `ESC \` or as C1, or at the end of the text.
        let strings = json!({ "message": "a\u{1b}P1q\u{1b}\\b \u{9d}x\u{9c}c \u{90}dcs\u{7}d \u{1b}]never" });
        assert_eq!(describe_error(&strings), "ab c d");
        // Clipped after stripping: escapes never count towards the 200.
        let long = json!({ "message": format!("{}{}", "\u{1b}[1m".repeat(300), "a".repeat(250)) });
        assert_eq!(describe_error(&long), format!("{}…", "a".repeat(200)));
    }

    /// A one-shot HTTP server answering every request with `head` + `body`.
    fn answer(head: String, body: Vec<u8>) -> String {
        use std::io::{BufRead, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                let mut out = stream;
                let _ = out.write_all(head.as_bytes()).and_then(|()| out.write_all(&body));
            }
        });
        url
    }

    fn chunked(chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for c in chunks {
            out.extend(format!("{:x}\r\n", c.len()).into_bytes());
            out.extend_from_slice(c);
            out.extend(b"\r\n");
        }
        out.extend(b"0\r\n\r\n");
        out
    }

    async fn prelogin_with_limit(url: &str, limit: usize) -> Result<KdfParams, ApiError> {
        let mut api = Api::new(resolve_server_urls(url).unwrap(), "d".into()).unwrap();
        api.body_limit = limit;
        api.prelogin("a@b.c").await
    }

    #[test]
    fn the_body_buffer_is_reserved_modestly_and_grown_into_wiped_copies() {
        assert_eq!(initial_capacity(None), 0);
        assert_eq!(initial_capacity(Some(10)), 10);
        assert_eq!(initial_capacity(Some(MAX_BODY)), 1024 * 1024, "a claimed length reserves at most 1 MiB");
        // Doubling, never past the cap, never below what is needed.
        assert_eq!(grown_capacity(0, 10, 100), 10);
        assert_eq!(grown_capacity(64, 65, 1000), 128);
        assert_eq!(grown_capacity(64, 65, 100), 100);
        let mut body = Zeroizing::new(Vec::with_capacity(initial_capacity(Some(4))));
        for chunk in [&b"abcd"[..], b"efgh", b"ijklmnop", b"q"] {
            append_wiped(&mut body, chunk, 100);
            assert!(body.capacity() <= 100);
        }
        assert_eq!(body.as_slice(), b"abcdefghijklmnopq");
    }

    #[tokio::test]
    async fn response_bodies_are_capped_while_they_are_read() {
        assert_eq!(MAX_BODY, 256 * 1024 * 1024);
        let kdf = br#"{"kdf":0,"kdfIterations":600000}"#.to_vec();
        let plain =
            |body: &[u8]| format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let streamed = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_owned();

        let ok = answer(plain(&kdf), kdf.clone());
        assert!(matches!(prelogin_with_limit(&ok, 64).await, Ok(KdfParams::Pbkdf2 { iterations: 600_000 })));

        // Announced as too large: refused before the body is read.
        let announced = answer(
            "HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\nConnection: close\r\n\r\n".to_owned(),
            kdf.clone(),
        );
        let e = prelogin_with_limit(&announced, 64).await.unwrap_err();
        assert!(matches!(&e, ApiError::Protocol(m) if m.contains("larger than 64 bytes")), "{e}");

        // Streamed without a length: refused once the chunks pass the cap.
        let big = vec![b' '; 40];
        let streams = answer(streamed.clone(), chunked(&[&big, &big, &kdf]));
        let e = prelogin_with_limit(&streams, 64).await.unwrap_err();
        assert!(matches!(&e, ApiError::Protocol(m) if m.contains("larger than 64 bytes")), "{e}");
        let (head, tail) = kdf.split_at(10);
        let fits = answer(streamed, chunked(&[head, tail]));
        assert!(prelogin_with_limit(&fits, 64).await.is_ok());

        // An error answer is capped too.
        let error = answer(plain(&big).replace("200 OK", "500 X"), big.clone());
        let e = prelogin_with_limit(&error, 16).await.unwrap_err();
        assert!(matches!(&e, ApiError::Protocol(m) if m.contains("larger than 16 bytes")), "{e}");
    }

    #[tokio::test]
    async fn prelogin_reads_both_kdf_kinds_and_refuses_others() {
        let reply = |json: &str| {
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", json.len());
            answer(head, json.as_bytes().to_vec())
        };
        let argon = reply(r#"{"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":4}"#);
        assert_eq!(
            prelogin_with_limit(&argon, 1024).await.unwrap(),
            KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 }
        );
        // A missing parameter reads as 0, which validation rejects later.
        let bare = reply(r#"{"kdf":1}"#);
        assert_eq!(
            prelogin_with_limit(&bare, 1024).await.unwrap(),
            KdfParams::Argon2id { iterations: 0, memory_mib: 0, parallelism: 0 }
        );
        let other = reply(r#"{"kdf":7}"#);
        let e = prelogin_with_limit(&other, 1024).await.unwrap_err();
        assert!(matches!(&e, ApiError::Protocol(m) if m == "unsupported KDF type Some(7)"), "{e}");
    }

    #[tokio::test]
    async fn a_body_that_is_not_utf8_is_read_lossily() {
        let body = b"{\"message\":\"bad \xff byte\"}".to_vec();
        let head = format!("HTTP/1.1 400 Bad\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let url = answer(head, body);
        let e = prelogin_with_limit(&url, 1024).await.unwrap_err();
        assert!(matches!(&e, ApiError::Http { status: 400, message } if message == "bad \u{fffd} byte"), "{e}");
    }

    #[test]
    fn a_client_that_cannot_be_built_is_a_network_error() {
        let e = build_client(reqwest::Client::builder().user_agent("bad\nagent")).unwrap_err();
        assert!(matches!(&e, ApiError::Network(m) if !m.is_empty()), "{e}");
        assert!(e.is_transient());
    }

    #[tokio::test]
    async fn a_body_cut_short_is_a_network_error() {
        // The server announces 1000 bytes, sends 5 and hangs up.
        let url = answer(
            "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n".to_owned(),
            b"short".to_vec(),
        );
        let e = prelogin_with_limit(&url, 4096).await.unwrap_err();
        assert!(matches!(e, ApiError::Network(_)), "{e}");
    }

    #[tokio::test]
    async fn a_sync_without_a_profile_is_refused() {
        let body = br#"{"ciphers":[]}"#.to_vec();
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let url = answer(head, body);
        let mut api = Api::new(resolve_server_urls(&url).unwrap(), "d".into()).unwrap();
        api.token = Some((Zeroizing::new("tok".into()), Instant::now() + Duration::from_secs(60)));
        let e = api.sync().await.unwrap_err();
        assert!(matches!(&e, ApiError::Protocol(m) if m == "sync response has no profile"), "{e}");
        assert!(api.user_id.is_none());
    }

    #[test]
    fn validation_errors_are_part_of_the_server_text() {
        let body = json!({ "message": "invalid", "validationErrors": { "Name": ["too long"] } });
        assert_eq!(describe_error(&body), r#"invalid {"Name":["too long"]}"#);
    }

    #[test]
    fn normalizes_empty_keys_unchanged() {
        assert_eq!(normalize_keys(json!({ "": 1, "AbC": 2 })), json!({ "": 1, "abC": 2 }));
    }

    #[test]
    fn normalizes_pascal_case() {
        let v = normalize_keys(json!({ "Profile": { "Key": "k" }, "Ciphers": [{ "RevisionDate": "d" }] }));
        assert_eq!(v, json!({ "profile": { "key": "k" }, "ciphers": [{ "revisionDate": "d" }] }));
    }

    #[test]
    fn writing_before_a_sync_is_transient() {
        // A logout (and a new login) during a flush clears the profile: the
        // op must wait for the next sync, never be dropped.
        let api = Api::new(resolve_server_urls("http://127.0.0.1:1").unwrap(), "d".into()).unwrap();
        let e = api.with_owner(Map::new()).unwrap_err();
        assert!(e.is_transient(), "{e}");
    }

    #[test]
    fn out_of_date_detection() {
        let e = ApiError::Http { status: 400, message: "The cipher you are updating is out of date".into() };
        assert!(e.is_out_of_date());
        assert!(!ApiError::Http { status: 500, message: "out of date".into() }.is_out_of_date());
        assert!(ApiError::Network("x".into()).is_transient());
    }
}
