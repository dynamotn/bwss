//! Minimal Bitwarden REST client: prelogin, API-key login, sync, folders and
//! item writes. Items are kept as JSON values so that edits pass every field
//! this client does not model straight back to the server.

use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use url::Url;

use super::crypto::KdfParams;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("network error: {0}")]
    Network(String),
    #[error("HTTP {status}{}", if .message.is_empty() { String::new() } else { format!(" (server says: {})", .message) })]
    Http { status: u16, message: String },
    #[error("unexpected response: {0}")]
    Protocol(String),
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

#[derive(Debug, Clone)]
pub struct ApiKey {
    pub client_id: String,
    pub client_secret: String,
}

// DeviceType.LinuxDesktop in the Bitwarden server enum.
const DEVICE_TYPE: &str = "8";
const CLIENT_NAME: &str = "bwss";

pub struct Api {
    urls: ServerUrls,
    http: reqwest::Client,
    device_id: String,
    token: Option<(String, Instant)>,
    user_id: Option<String>,
}

impl Api {
    pub fn new(urls: ServerUrls, device_id: String) -> Result<Self, ApiError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            // A redirect could carry the API key to another host.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("bwss/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ApiError::Network(e.to_string()))?;
        Ok(Api { urls, http, device_id, token: None, user_id: None })
    }

    pub fn urls(&self) -> &ServerUrls {
        &self.urls
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Value, ApiError> {
        let res = req
            .header("Bitwarden-Client-Name", CLIENT_NAME)
            .header("Bitwarden-Client-Version", env!("CARGO_PKG_VERSION"))
            .header("Device-Type", DEVICE_TYPE)
            .send()
            .await
            .map_err(|e| ApiError::Network(e.without_url().to_string()))?;
        let status = res.status().as_u16();
        let text = res.text().await.map_err(|e| ApiError::Network(e.without_url().to_string()))?;
        let body = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).map(normalize_keys).unwrap_or(Value::Null)
        };
        if !(200..300).contains(&status) {
            return Err(ApiError::Http { status, message: describe_error(&body) });
        }
        Ok(body)
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
    pub async fn login(&mut self, key: &ApiKey) -> Result<(), ApiError> {
        let form = [
            ("grant_type", "client_credentials"),
            ("scope", "api"),
            ("client_id", key.client_id.as_str()),
            ("client_secret", key.client_secret.as_str()),
            ("deviceType", DEVICE_TYPE),
            ("deviceIdentifier", self.device_id.as_str()),
            ("deviceName", "bwss"),
        ];
        let body = self.send(self.http.post(format!("{}/connect/token", self.urls.identity)).form(&form)).await?;
        let token = body
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::Protocol("no access token".into()))?;
        let ttl = body.get("expires_in").and_then(Value::as_u64).unwrap_or(3600).saturating_sub(60).max(60);
        self.token = Some((token.to_owned(), Instant::now() + Duration::from_secs(ttl)));
        Ok(())
    }

    pub fn is_logged_in(&self) -> bool {
        self.token.as_ref().is_some_and(|(_, exp)| *exp > Instant::now())
    }

    pub fn logout(&mut self) {
        self.token = None;
        self.user_id = None;
    }

    fn authed(&self, req: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder, ApiError> {
        match &self.token {
            Some((t, exp)) if *exp > Instant::now() => Ok(req.bearer_auth(t)),
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

    pub async fn create_folder(&self, encrypted_name: &str) -> Result<Value, ApiError> {
        let req = self.authed(self.http.post(format!("{}/folders", self.urls.api)))?;
        self.send(req.json(&json!({ "name": encrypted_name }))).await
    }

    pub async fn delete_folder(&self, id: &str) -> Result<(), ApiError> {
        let req = self.authed(self.http.delete(format!("{}/folders/{}", self.urls.api, enc(id))))?;
        self.send(req).await.map(|_| ())
    }

    fn with_owner(&self, mut body: Map<String, Value>) -> Result<Value, ApiError> {
        // Required by Vaultwarden 1.37+, optional on bitwarden.com.
        let owner = self.user_id.clone().ok_or_else(|| ApiError::Protocol("sync before writing items".into()))?;
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

fn enc(segment: &str) -> String {
    url::form_urlencoded::byte_serialize(segment.as_bytes()).collect()
}

/// Server text is untrusted: keep it short.
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
    let text = parts.join(" ").split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() > 200 { text.chars().take(200).collect::<String>() + "…" } else { text }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(resolve_server_urls("https://u:p@bw.example.org").is_err());
    }

    #[test]
    fn normalizes_pascal_case() {
        let v = normalize_keys(json!({ "Profile": { "Key": "k" }, "Ciphers": [{ "RevisionDate": "d" }] }));
        assert_eq!(v, json!({ "profile": { "key": "k" }, "ciphers": [{ "revisionDate": "d" }] }));
    }

    #[test]
    fn out_of_date_detection() {
        let e = ApiError::Http { status: 400, message: "The cipher you are updating is out of date".into() };
        assert!(e.is_out_of_date());
        assert!(!ApiError::Http { status: 500, message: "out of date".into() }.is_out_of_date());
        assert!(ApiError::Network("x".into()).is_transient());
    }
}
