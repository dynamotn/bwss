//! Configuration and file locations.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    #[default]
    Bitwarden,
    Memory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AclMode {
    /// Ask before an application uses an item it did not create.
    #[default]
    Prompt,
    /// No per-application checks (gnome-keyring behaviour).
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub backend: BackendKind,
    pub server_url: String,
    pub email: String,
    /// The keyring folder: where bwss puts the items it creates.
    pub folder: String,
    /// pinentry-compatible program used for every prompt.
    pub prompter: String,
    pub acl: AclMode,
    /// Lock after this many minutes without use (0 = never).
    pub idle_lock_minutes: u64,
    /// Pull remote changes this often while unlocked.
    pub sync_interval_seconds: u64,
    /// Master password of the memory backend (tests and demos only).
    pub memory_password: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            backend: BackendKind::Bitwarden,
            server_url: "https://vault.bitwarden.com".into(),
            email: String::new(),
            folder: "secret-service".into(),
            prompter: "pinentry".into(),
            acl: AclMode::Prompt,
            idle_lock_minutes: 0,
            sync_interval_seconds: 300,
            memory_password: "bwss".into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials").field("client_id", &self.client_id).field("client_secret", &"<redacted>").finish()
    }
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| {
        std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/")).join(fallback)
    })
}

pub struct Paths {
    pub config: PathBuf,
    pub credentials: PathBuf,
    pub cache: PathBuf,
    pub state: PathBuf,
    /// Device state under the dybw layout (`$XDG_STATE_HOME/dybw/tools/bwss`).
    pub tool_state: PathBuf,
}

impl Paths {
    pub fn from_env() -> Self {
        let config_dir = xdg("XDG_CONFIG_HOME", ".config").join("bwss");
        Paths {
            config: config_dir.join("config.toml"),
            credentials: config_dir.join("credentials.toml"),
            cache: xdg("XDG_CACHE_HOME", ".cache").join("bwss"),
            state: xdg("XDG_STATE_HOME", ".local/state").join("bwss"),
            tool_state: xdg("XDG_STATE_HOME", ".local/state").join("dybw/tools/bwss"),
        }
    }
}

pub fn load_config(paths: &Paths) -> anyhow::Result<Config> {
    match std::fs::read_to_string(&paths.config) {
        Ok(text) => Ok(toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", paths.config.display()))?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(anyhow::anyhow!("{}: {e}", paths.config.display())),
    }
}

pub fn load_credentials(paths: &Paths) -> anyhow::Result<Credentials> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(&paths.credentials)
            .map_err(|e| anyhow::anyhow!("{}: {e} (run `bwss login`)", paths.credentials.display()))?;
        if meta.mode() & 0o077 != 0 {
            anyhow::bail!("{} must not be readable by others (chmod 600)", paths.credentials.display());
        }
    }
    let text = Zeroizing::new(std::fs::read_to_string(&paths.credentials)?);
    Ok(toml::from_str(&text)?)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    /// Compiles only while the secret is wiped on drop.
    fn _assert_zeroizing(c: &Credentials) -> &Zeroizing<String> {
        &c.client_secret
    }

    #[test]
    fn credentials_debug_is_redacted() {
        let c = Credentials { client_id: "the-id".into(), client_secret: Zeroizing::new("hunter2-secret".into()) };
        let out = format!("{c:?}");
        assert!(!out.contains("hunter2-secret"));
        assert!(out.contains("<redacted>"));
        assert!(out.contains("the-id"));
    }

    #[cfg(unix)]
    #[test]
    fn credentials_load_into_zeroizing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        std::fs::write(&path, "client_id = \"cid\"\nclient_secret = \"csecret\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let paths = Paths {
            config: dir.path().join("config.toml"),
            credentials: path,
            cache: dir.path().join("cache"),
            state: dir.path().join("state"),
            tool_state: dir.path().join("tool-state"),
        };
        let c = load_credentials(&paths).unwrap();
        assert_eq!(c.client_id, "cid");
        assert_eq!(c.client_secret.as_str(), "csecret");
    }
}
