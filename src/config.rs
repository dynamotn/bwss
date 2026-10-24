//! Configuration (ADR 0008): the shared dybw file, bwss's device state and
//! file locations.
//!
//! bwss reads `$XDG_CONFIG_HOME/dybw/config.toml`: the top level and the
//! profile it serves are checked against the key registry of dybw profiles
//! §1, `[bwss]` strictly, and every other table is ignored. Nothing in the
//! file may weaken a check: `acl` is refused anywhere,
//! `index_derived_attributes` in `[bwss]`, and `pinentry` must name a
//! program the user cannot replace.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use toml::{Table, Value};
use zeroize::Zeroizing;

use crate::fsutil::User;

pub const DEFAULT_LOCK_TIMEOUT_MINUTES: u64 = 60;
pub const DEFAULT_SYNC_INTERVAL_SECONDS: u64 = 300;
pub const DEFAULT_PINENTRY: &str = "pinentry";
pub const DEFAULT_FOLDER: &str = "secret-service";
pub const DEFAULT_MEMORY_PASSWORD: &str = "bwss";
const DEFAULT_AUTH: &str = "api-key";

/// The scalar keys allowed at the top level (dybw profiles §1).
pub const TOP_LEVEL_KEYS: &[&str] =
    &["default", "auth", "lock_timeout_minutes", "sync_interval_seconds", "pinentry", "clipboard_clear_seconds"];
/// The keys allowed in `[profiles.<name>]` (dybw profiles §1).
pub const PROFILE_KEYS: &[&str] =
    &["server_url", "email", "auth", "lock_timeout_minutes", "sync_interval_seconds", "pinentry"];
/// The keys of `[bwss]` (ADR 0008).
pub const BWSS_KEYS: &[&str] = &["profile", "folder", "backend", "memory_password"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    #[default]
    Bitwarden,
    Memory,
}

/// Per-application access control: device state, never read from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AclMode {
    /// Ask before an application uses an item it did not create.
    #[default]
    Prompt,
    /// No per-application checks (gnome-keyring behaviour).
    Off,
}

/// The account of the profile bwss serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub profile: String,
    pub server_url: String,
    pub email: String,
}

/// What the file says for bwss, resolved, before `pinentry` is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub backend: BackendKind,
    /// `None` only for the memory backend without a profile.
    pub account: Option<Account>,
    pub folder: String,
    pub memory_password: String,
    pub lock_timeout_minutes: u64,
    pub sync_interval_seconds: u64,
    /// As written: a program name or an absolute path.
    pub pinentry: String,
}

/// What the daemon runs with.
#[derive(Debug, Clone)]
pub struct Config {
    pub backend: BackendKind,
    /// The profile bwss serves (`None`: memory backend without one).
    pub profile: Option<String>,
    pub server_url: String,
    pub email: String,
    /// The keyring folder: where bwss puts the items it creates.
    pub folder: String,
    /// The checked, absolute path of the pinentry used for every prompt.
    pub pinentry: String,
    pub acl: AclMode,
    /// Lock after this many minutes without use (0 = never).
    pub lock_timeout_minutes: u64,
    /// Pull remote changes this often while unlocked.
    pub sync_interval_seconds: u64,
    /// Master password of the memory backend (tests and demos only).
    pub memory_password: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            backend: BackendKind::Bitwarden,
            profile: None,
            server_url: "https://vault.bitwarden.com".into(),
            email: String::new(),
            folder: DEFAULT_FOLDER.into(),
            pinentry: DEFAULT_PINENTRY.into(),
            acl: AclMode::Prompt,
            lock_timeout_minutes: DEFAULT_LOCK_TIMEOUT_MINUTES,
            sync_interval_seconds: DEFAULT_SYNC_INTERVAL_SECONDS,
            memory_password: DEFAULT_MEMORY_PASSWORD.into(),
        }
    }
}

/// The API key of a profile, bound to the identity origin it was entered for.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    /// `scheme://host[:port]` of the identity server the key may be sent to.
    pub identity_origin: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("identity_origin", &self.identity_origin)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

pub struct Paths {
    /// The shared dybw file.
    pub config: PathBuf,
    /// bwss's own file before ADR 0008, read only by `bwss config migrate`.
    pub legacy_config: PathBuf,
    pub legacy_credentials: PathBuf,
    /// Offline cache and locked index.
    pub cache: PathBuf,
    /// Offline queue (and, before ADR 0008, the device id).
    pub state: PathBuf,
    /// `$XDG_STATE_HOME/dybw/profiles`.
    pub profiles: PathBuf,
    /// Device state under the dybw layout (`$XDG_STATE_HOME/dybw/tools/bwss`).
    pub tool_state: PathBuf,
}

impl Paths {
    pub fn from_env() -> Self {
        Self::with(|var| std::env::var_os(var))
    }

    /// The locations for an environment read through `var`.
    pub fn with(var: impl Fn(&str) -> Option<OsString>) -> Self {
        let home = var("HOME").map_or_else(|| PathBuf::from("/"), PathBuf::from);
        let xdg = |name: &str, fallback: &str| {
            var(name).map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| home.join(fallback))
        };
        let config = xdg("XDG_CONFIG_HOME", ".config");
        let state = xdg("XDG_STATE_HOME", ".local/state");
        Paths {
            config: config.join("dybw/config.toml"),
            legacy_config: config.join("bwss/config.toml"),
            legacy_credentials: config.join("bwss/credentials.toml"),
            cache: xdg("XDG_CACHE_HOME", ".cache").join("bwss"),
            state: state.join("bwss"),
            profiles: state.join("dybw/profiles"),
            tool_state: state.join("dybw/tools/bwss"),
        }
    }

    pub fn profile_dir(&self, profile: &str) -> PathBuf {
        self.profiles.join(profile)
    }

    pub fn credentials(&self, profile: &str) -> PathBuf {
        self.profile_dir(profile).join("credentials")
    }

    /// Each frontend's device identifier (profiles §3).
    pub fn devices(&self, profile: &str) -> PathBuf {
        self.profile_dir(profile).join("devices")
    }

    pub fn device_id(&self, profile: &str) -> PathBuf {
        self.devices(profile).join("bwss")
    }

    /// Present when the ACL is off on this device.
    pub fn acl_off(&self) -> PathBuf {
        self.tool_state.join("acl-off")
    }

    /// The locked index (design §7).
    pub fn locked_index(&self) -> PathBuf {
        self.cache.join("locked-index.json")
    }

    /// Present when derived attributes go in the locked index on this device.
    pub fn index_derived(&self) -> PathBuf {
        self.tool_state.join("index-derived")
    }
}

/// `acl` where bwss reads keys: the top level, its profile or `[bwss]`.
/// Other tools' tables are theirs and never read.
fn acl_moved(at: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "`acl` in {at} is not read from the config file any more: turn the ACL off on this device \
         with `bwss acl off` instead (ADR 0008)"
    )
}

fn string<'a>(table: &'a Table, key: &str, at: &str) -> anyhow::Result<Option<&'a str>> {
    match table.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => bail!("`{key}` in {at} must be a string"),
    }
}

fn count(table: &Table, key: &str, at: &str) -> anyhow::Result<Option<u64>> {
    match table.get(key) {
        None => Ok(None),
        Some(Value::Integer(n)) => match u64::try_from(*n) {
            Ok(n) => Ok(Some(n)),
            Err(_) => bail!("`{key}` in {at} must not be negative"),
        },
        Some(_) => bail!("`{key}` in {at} must be a whole number"),
    }
}

/// Type-checks the registry keys that `table` (the top level or a profile)
/// holds, whether or not bwss uses them.
fn check_registry_values(table: &Table, at: &str) -> anyhow::Result<()> {
    string(table, "default", at)?;
    string(table, "server_url", at)?;
    string(table, "email", at)?;
    if let Some(auth) = string(table, "auth", at)?
        && !matches!(auth, "api-key" | "password")
    {
        bail!("`auth` in {at} must be \"api-key\" or \"password\", not {auth:?}");
    }
    for key in ["lock_timeout_minutes", "sync_interval_seconds", "clipboard_clear_seconds"] {
        count(table, key, at)?;
    }
    if string(table, "pinentry", at)?.is_some_and(str::is_empty) {
        bail!("`pinentry` in {at} must not be empty");
    }
    Ok(())
}

fn check_top_level(doc: &Table) -> anyhow::Result<()> {
    const AT: &str = "the top level";
    for (key, value) in doc {
        match (key.as_str(), value) {
            ("profiles", Value::Table(profiles)) => {
                if let Some((name, _)) = profiles.iter().find(|(_, p)| !p.is_table()) {
                    bail!("`profiles.{name}` must be a table: [profiles.{name}]");
                }
            }
            // Other tools' tables (and arrays of tables) are theirs.
            (_, Value::Table(_)) => {}
            (_, Value::Array(a)) if !a.is_empty() && a.iter().all(Value::is_table) => {}
            ("acl", _) => return Err(acl_moved(AT)),
            (k, _) if TOP_LEVEL_KEYS.contains(&k) => {}
            (k, _) if PROFILE_KEYS.contains(&k) => bail!("`{k}` belongs in a profile, not at {AT}"),
            (k, _) => bail!("unknown key `{k}` at {AT}"),
        }
    }
    check_registry_values(doc, AT)
}

fn check_profile(profile: &Table, at: &str) -> anyhow::Result<()> {
    for key in profile.keys() {
        if PROFILE_KEYS.contains(&key.as_str()) {
            continue;
        }
        if key == "acl" {
            return Err(acl_moved(at));
        }
        if TOP_LEVEL_KEYS.contains(&key.as_str()) {
            bail!("`{key}` in {at} is shared by every profile: set it at the top level");
        }
        bail!("unknown key `{key}` in {at}");
    }
    check_registry_values(profile, at)
}

fn check_profile_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        bail!("{name:?} cannot be a profile name: it names a directory");
    }
    Ok(())
}

/// Resolves bwss's settings from a parsed dybw file.
pub fn resolve(doc: &Table) -> anyhow::Result<Settings> {
    check_top_level(doc)?;
    // A `bwss` that is not a table was refused as an unknown key.
    let empty = Table::new();
    let bwss = doc.get("bwss").and_then(Value::as_table).unwrap_or(&empty);
    if let Some(key) = bwss.keys().find(|k| !BWSS_KEYS.contains(&k.as_str())) {
        if key == "acl" {
            return Err(acl_moved("[bwss]"));
        }
        if key == "index_derived_attributes" {
            bail!(
                "`index_derived_attributes` in [bwss] is not read from the config file: a synced file must never \
                 weaken the locked index. Put derived attributes in it on this device with `bwss index derived on`"
            );
        }
        bail!("unknown key `{key}` in [bwss]");
    }
    let backend = match string(bwss, "backend", "[bwss]")? {
        None | Some("bitwarden") => BackendKind::Bitwarden,
        Some("memory") => BackendKind::Memory,
        Some(other) => bail!("`backend` in [bwss] must be \"bitwarden\" or \"memory\", not {other:?}"),
    };
    let folder = string(bwss, "folder", "[bwss]")?.unwrap_or(DEFAULT_FOLDER).to_owned();
    let memory_password = string(bwss, "memory_password", "[bwss]")?.unwrap_or(DEFAULT_MEMORY_PASSWORD).to_owned();

    let name = match string(bwss, "profile", "[bwss]")? {
        Some(name) => Some(name),
        None => string(doc, "default", "the top level")?,
    };
    let profile = match name {
        Some(name) => {
            check_profile_name(name)?;
            let at = format!("[profiles.{name}]");
            let Some(profile) = doc.get("profiles").and_then(|p| p.get(name)).and_then(Value::as_table) else {
                bail!("bwss serves profile {name:?}, which is not defined: add {at}");
            };
            check_profile(profile, &at)?;
            let required = |key: &str| -> anyhow::Result<String> {
                string(profile, key, &at)?.map(str::to_owned).with_context(|| format!("`{key}` is required in {at}"))
            };
            let account =
                Account { profile: name.to_owned(), server_url: required("server_url")?, email: required("email")? };
            Some((account, profile))
        }
        None if backend == BackendKind::Memory => None,
        None => bail!("bwss needs a profile: set `default` at the top level, or `profile` in [bwss]"),
    };
    let own = profile.as_ref().map(|(_, p)| *p);

    // The served profile, then the top level, then the built-in default.
    // Both places are type-checked above.
    let setting = |key: &str| own.and_then(|p| p.get(key)).or_else(|| doc.get(key));
    let number = |key: &str, default: u64| {
        setting(key).and_then(Value::as_integer).and_then(|n| u64::try_from(n).ok()).unwrap_or(default)
    };
    let text = |key: &str, default: &'static str| setting(key).and_then(Value::as_str).unwrap_or(default).to_owned();
    let auth = text("auth", DEFAULT_AUTH);
    if backend == BackendKind::Bitwarden && auth != DEFAULT_AUTH {
        bail!("bwss does not support `auth = {auth:?}`; it logs in with an API key only (`auth = \"api-key\"`)");
    }
    Ok(Settings {
        backend,
        account: profile.map(|(a, _)| a),
        folder,
        memory_password,
        lock_timeout_minutes: number("lock_timeout_minutes", DEFAULT_LOCK_TIMEOUT_MINUTES),
        sync_interval_seconds: number("sync_interval_seconds", DEFAULT_SYNC_INTERVAL_SECONDS),
        pinentry: text("pinentry", DEFAULT_PINENTRY),
    })
}

/// Why a pinentry was accepted (ADR 0008).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinentryRule {
    /// Neither the program nor any directory above it is writable by the user.
    NotWritable,
    /// It lies under bwss's own installation prefix (Homebrew).
    SamePrefix(PathBuf),
}

impl std::fmt::Display for PinentryRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinentryRule::NotWritable => f.write_str("not writable by this user"),
            PinentryRule::SamePrefix(p) => write!(f, "under bwss's own installation prefix {}", p.display()),
        }
    }
}

/// Which programs may ask for the master password.
#[derive(Debug, Clone)]
pub struct Trust {
    /// `PATH`, to resolve a bare program name.
    pub search: Option<OsString>,
    pub user: User,
    /// bwss's own resolved executable, for the install-prefix rule.
    pub exe: Option<PathBuf>,
    /// The user's resolved home: no prefix in, at or above it is trusted.
    pub home: Option<PathBuf>,
}

/// bwss's installation prefix: the parent of a `Cellar` directory in its
/// path (a Homebrew keg: `/opt/homebrew` for
/// `/opt/homebrew/Cellar/bwss/1.0/bin/bwss`), otherwise the grandparent of
/// the executable.
pub fn install_prefix(exe: &Path) -> Option<PathBuf> {
    match exe.ancestors().find(|dir| dir.file_name().is_some_and(|n| n == "Cellar")) {
        Some(cellar) => cellar.parent().map(Path::to_owned),
        None => exe.parent().and_then(Path::parent).map(Path::to_owned),
    }
}

/// Why `prefix` cannot be trusted as an installation prefix, if it cannot.
fn prefix_problem(prefix: &Path, home: Option<&Path>) -> Option<String> {
    let shown = prefix.display();
    if prefix.parent().is_none() {
        return Some("bwss's prefix would be `/`".to_owned());
    }
    let Some(home) = home else {
        return Some("the home directory is unknown".to_owned());
    };
    if prefix == home {
        Some(format!("bwss's prefix {shown} is your home"))
    } else if home.starts_with(prefix) {
        Some(format!("bwss's prefix {shown} contains your home"))
    } else if prefix.starts_with(home) {
        Some(format!("bwss's prefix {shown} is inside your home"))
    } else {
        None
    }
}

/// Whether `file` is in one of the prefix's program directories:
/// `bin`, `sbin`, `opt/*/bin` or `Cellar/*/*/bin`.
fn in_prefix_bin(prefix: &Path, file: &Path) -> bool {
    let Ok(rest) = file.strip_prefix(prefix) else { return false };
    let parts: Vec<&str> = rest.iter().map(|p| p.to_str().unwrap_or("/")).collect();
    matches!(parts.as_slice(), ["bin" | "sbin", _] | ["opt", _, "bin", _] | ["Cellar", _, _, "bin", _])
}

/// Whether a sticky directory keeps the user from replacing the entry below
/// it: world-writable and sticky, owned by someone else, and the entry not
/// the user's either.
fn sticky_shields(dir_mode: u32, dir_uid: u32, entry_uid: u32, user: &User) -> bool {
    let sticky_and_open = dir_mode & 0o1000 != 0 && dir_mode & 0o002 != 0;
    sticky_and_open && user.uid != 0 && dir_uid != user.uid && entry_uid != user.uid
}

impl Trust {
    pub fn system() -> anyhow::Result<Self> {
        let exe = std::env::current_exe().and_then(std::fs::canonicalize).context("cannot find this executable")?;
        Ok(Trust {
            search: std::env::var_os("PATH"),
            user: User::current().context("cannot tell which user this is")?,
            exe: Some(exe),
            home: std::env::var_os("HOME").and_then(|h| std::fs::canonicalize(h).ok()),
        })
    }

    /// The resolved path of `pinentry`, if it is a trusted program, and why.
    pub fn check(&self, pinentry: &str) -> anyhow::Result<(PathBuf, PinentryRule)> {
        let path = self.locate(pinentry)?;
        let resolved = std::fs::canonicalize(&path).with_context(|| format!("pinentry {}", path.display()))?;
        let rule = self.verify(&resolved)?;
        Ok((resolved, rule))
    }

    /// The rule again for a path `check` resolved: run before every spawn.
    pub fn verify(&self, resolved: &Path) -> anyhow::Result<PinentryRule> {
        let shown = resolved.display();
        let now = std::fs::canonicalize(resolved).with_context(|| format!("pinentry {shown}"))?;
        ensure!(now == resolved, "pinentry {shown} now resolves to {}", now.display());
        let meta = std::fs::metadata(resolved).with_context(|| format!("pinentry {shown}"))?;
        ensure!(meta.is_file(), "pinentry {shown} is not a program");
        let Some(writable) = self.writable_part(resolved) else {
            return Ok(PinentryRule::NotWritable);
        };
        match self.prefix_rule(resolved) {
            Ok(prefix) => Ok(PinentryRule::SamePrefix(prefix)),
            Err(why) => bail!(
                "pinentry {shown}: {} is writable by this user, so the program cannot be trusted \
                 (and the install-prefix rule does not apply: {why})",
                writable.display()
            ),
        }
    }

    /// The prefix under which `resolved` is trusted as bwss's neighbour
    /// (controller ruling R15, stricter than ADR 0008), or why not.
    fn prefix_rule(&self, resolved: &Path) -> Result<PathBuf, String> {
        let exe = self.exe.as_deref().ok_or("bwss's own executable is unknown")?;
        let exe_writable = std::fs::metadata(exe).is_ok_and(|m| self.user.may_write_file(&m));
        if !exe_writable {
            return Err(format!(
                "bwss itself ({}) is not writable by this user, so nothing beside it is trusted for that",
                exe.display()
            ));
        }
        let prefix = install_prefix(exe).ok_or_else(|| format!("{} has no installation prefix", exe.display()))?;
        if let Some(problem) = prefix_problem(&prefix, self.home.as_deref()) {
            return Err(problem);
        }
        if !in_prefix_bin(&prefix, resolved) {
            return Err(format!(
                "it is not in a program directory of bwss's prefix {} (bin, sbin, opt/*/bin, Cellar/*/*/bin)",
                prefix.display()
            ));
        }
        Ok(prefix)
    }

    /// The program itself, or the first directory above it, that this user
    /// could change. A sticky directory (`/tmp`) owned by someone else does
    /// not count when the entry below it is not the user's either: the
    /// sticky bit lets the user replace only their own entries.
    fn writable_part(&self, file: &Path) -> Option<PathBuf> {
        use std::os::unix::fs::MetadataExt;
        let changeable = |p: &Path| std::fs::metadata(p).map_or(true, |m| self.user.may_write_file(&m));
        if changeable(file) {
            return Some(file.to_owned());
        }
        let mut below = file;
        for dir in file.ancestors().skip(1) {
            let meta = std::fs::metadata(dir);
            let open = meta.as_ref().map_or(true, |m| self.user.may_write_file(m));
            let shielded = match (&meta, std::fs::symlink_metadata(below)) {
                (Ok(dir), Ok(entry)) => sticky_shields(dir.mode(), dir.uid(), entry.uid(), &self.user),
                _ => false,
            };
            if open && !shielded {
                return Some(dir.to_owned());
            }
            below = dir;
        }
        None
    }

    /// `pinentry` as an absolute path: as given, or the first match on `PATH`.
    fn locate(&self, pinentry: &str) -> anyhow::Result<PathBuf> {
        if pinentry.is_empty() {
            bail!("`pinentry` is empty");
        }
        if pinentry.contains('/') {
            let path = PathBuf::from(pinentry);
            if !path.is_absolute() {
                bail!("pinentry {pinentry:?} must be an absolute path or a program name");
            }
            return Ok(path);
        }
        let search = self.search.as_deref().map(std::env::split_paths).into_iter().flatten();
        search
            .filter(|dir| dir.is_absolute())
            .map(|dir| dir.join(pinentry))
            .find(|p| p.is_file())
            .with_context(|| format!("pinentry {pinentry:?} not found in PATH"))
    }
}

/// bwss holds one user's vault and never runs as root (ADR 0008).
pub fn refuse_root(user: &User) -> anyhow::Result<()> {
    ensure!(
        user.uid != 0,
        "bwss does not run as root: it serves one user's vault, and root can replace any program it would trust"
    );
    Ok(())
}

/// Reads the dybw file; `None` when there is none.
pub fn read_doc(path: &Path) -> anyhow::Result<Option<Table>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(toml::from_str(&text).with_context(|| path.display().to_string())?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::new(e).context(path.display().to_string())),
    }
}

/// The settings from the dybw file. Refuses to guess when only bwss's old
/// file exists.
pub fn load_settings(paths: &Paths) -> anyhow::Result<Settings> {
    let doc = read_doc(&paths.config)?;
    let has_bwss = doc.as_ref().is_some_and(|d| d.contains_key("bwss"));
    if !has_bwss && std::fs::symlink_metadata(&paths.legacy_config).is_ok() {
        bail!(
            "{} is bwss's old config and {} has no [bwss] section yet: run `bwss config migrate`",
            paths.legacy_config.display(),
            paths.config.display()
        );
    }
    resolve(&doc.unwrap_or_default()).with_context(|| paths.config.display().to_string())
}

/// Everything the daemon needs, checked.
pub fn load(paths: &Paths, trust: &Trust) -> anyhow::Result<Config> {
    let s = load_settings(paths)?;
    let (pinentry, rule) = trust.check(&s.pinentry).with_context(|| paths.config.display().to_string())?;
    tracing::info!("pinentry {} accepted: {rule}", pinentry.display());
    let (profile, server_url, email) = match s.account {
        Some(a) => (Some(a.profile), a.server_url, a.email),
        None => (None, String::new(), String::new()),
    };
    Ok(Config {
        backend: s.backend,
        profile,
        server_url,
        email,
        folder: s.folder,
        pinentry: pinentry.to_string_lossy().into_owned(),
        acl: acl_mode(paths),
        lock_timeout_minutes: s.lock_timeout_minutes,
        sync_interval_seconds: s.sync_interval_seconds,
        memory_password: s.memory_password,
    })
}

/// Whether the device flag `path` is set: anything there counts, even a
/// dangling link.
pub fn flag_set(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Sets the device flag `path` (a private file holding `text`) or clears it.
fn set_flag(path: &Path, on: bool, text: &[u8]) -> std::io::Result<()> {
    if on {
        return crate::fsutil::write_private(path, text);
    }
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

pub fn acl_mode(paths: &Paths) -> AclMode {
    if flag_set(&paths.acl_off()) { AclMode::Off } else { AclMode::Prompt }
}

/// Turns the ACL off (or back on) on this device.
pub fn set_acl_off(paths: &Paths, off: bool) -> std::io::Result<()> {
    set_flag(&paths.acl_off(), off, b"off\n")
}

/// Puts derived attributes in the locked index on this device, or takes
/// them out again; the daemon reads it at every index write.
pub fn set_index_derived(paths: &Paths, on: bool) -> std::io::Result<()> {
    set_flag(&paths.index_derived(), on, b"on\n")
}

/// Reads a profile's API key: a regular file owned by `user`, mode 0600,
/// saved for `origin`.
pub fn load_credentials(path: &Path, user: &User, origin: &str) -> anyhow::Result<Credentials> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let shown = path.display();
    let link = std::fs::symlink_metadata(path).with_context(|| format!("{shown} (run `bwss login`)"))?;
    if link.file_type().is_symlink() {
        bail!("{shown} is a symbolic link; the API key must be a regular file");
    }
    if !link.is_file() {
        bail!("{shown} is not a regular file");
    }
    let mut file = std::fs::File::open(path).with_context(|| shown.to_string())?;
    let meta = file.metadata()?;
    // The file opened is the one checked above, not a link swapped in.
    ensure!((meta.dev(), meta.ino()) == (link.dev(), link.ino()), "{shown} changed while it was read");
    if meta.uid() != user.uid {
        bail!("{shown} is owned by uid {}, not by this user", meta.uid());
    }
    if meta.mode() & 0o077 != 0 {
        bail!("{shown} must not be readable by others (chmod 600)");
    }
    let mut text = Zeroizing::new(String::new());
    file.read_to_string(&mut text).with_context(|| shown.to_string())?;
    let creds: Credentials = parse_secret_toml(&text, path)?;
    if creds.identity_origin != origin {
        bail!(
            "the API key in {shown} was saved for {}, and the profile's server is now {origin}; \
             it is not sent there: run `bwss login` again",
            creds.identity_origin
        );
    }
    Ok(creds)
}

/// Parses a file that holds a secret. A TOML error quotes the source line,
/// so it is never passed on: only the path, the position, and the name of a
/// missing key (one of ours). An unknown key is not named: it could be a
/// pasted secret.
pub fn parse_secret_toml<T: serde::de::DeserializeOwned>(text: &str, path: &Path) -> anyhow::Result<T> {
    let e = match toml::from_str::<T>(text) {
        Ok(value) => return Ok(value),
        Err(e) => e,
    };
    let message = e.message();
    let missing = message.strip_prefix("missing field `").and_then(|rest| rest.split('`').next());
    let what = match missing {
        Some(key) => format!("missing key `{key}`"),
        None if message.starts_with("unknown field") => "an unknown key".to_owned(),
        None => "not valid TOML for this file".to_owned(),
    };
    let at = e.span().map(|span| {
        let before = text.get(..span.start).unwrap_or_default();
        let line = before.matches('\n').count() + 1;
        let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
        format!(" (line {line}, column {column})")
    });
    bail!("{}: {what}{}", path.display(), at.unwrap_or_default())
}

pub fn save_credentials(path: &Path, creds: &Credentials) -> anyhow::Result<()> {
    let text = Zeroizing::new(toml::to_string(creds)?);
    crate::fsutil::write_private(path, text.as_bytes()).with_context(|| path.display().to_string())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    fn doc(text: &str) -> Table {
        toml::from_str(text).unwrap()
    }

    fn err(text: &str) -> String {
        format!("{:#}", resolve(&doc(text)).unwrap_err())
    }

    const ACCOUNT: &str =
        "[profiles.personal]\nserver_url = \"https://vault.example.org\"\nemail = \"me@example.org\"\n";

    /// Compiles only while the secret is wiped on drop.
    fn _assert_zeroizing(c: &Credentials) -> &Zeroizing<String> {
        &c.client_secret
    }

    #[test]
    fn credentials_debug_is_redacted() {
        let c = Credentials {
            identity_origin: "https://identity.example.org".into(),
            client_id: "the-id".into(),
            client_secret: Zeroizing::new("hunter2-secret".into()),
        };
        let out = format!("{c:?}");
        assert!(!out.contains("hunter2-secret"));
        assert!(out.contains("<redacted>"));
        assert!(out.contains("the-id"));
    }

    // ---- the key registry -------------------------------------------------

    fn registry() -> Table {
        doc(include_str!("../tests/fixtures/config-registry.toml"))
    }

    fn keys_in(place: &str) -> Vec<String> {
        let reg = registry();
        let mut keys: Vec<String> = reg["keys"]
            .as_table()
            .unwrap()
            .iter()
            .filter(|(_, spec)| spec["where"].as_array().unwrap().iter().any(|w| w.as_str() == Some(place)))
            .map(|(k, _)| k.clone())
            .collect();
        keys.sort();
        keys
    }

    fn sorted(keys: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = keys.iter().map(|k| (*k).to_owned()).collect();
        v.sort();
        v
    }

    #[test]
    fn the_key_lists_mirror_the_registry() {
        assert_eq!(sorted(TOP_LEVEL_KEYS), keys_in("top"));
        assert_eq!(sorted(PROFILE_KEYS), keys_in("profile"));
        let reg = registry();
        let default = |k: &str| reg["keys"][k]["default"].clone();
        assert_eq!(default("lock_timeout_minutes").as_integer(), Some(60));
        assert_eq!(default("sync_interval_seconds").as_integer(), Some(300));
        assert_eq!(default("pinentry").as_str(), Some(DEFAULT_PINENTRY));
        assert_eq!(default("auth").as_str(), Some(DEFAULT_AUTH));
        assert_eq!(DEFAULT_LOCK_TIMEOUT_MINUTES, 60);
        assert_eq!(DEFAULT_SYNC_INTERVAL_SECONDS, 300);
    }

    /// A value of the right type for every registry key.
    fn sample(key: &str) -> &'static str {
        match key {
            "default" => "\"personal\"",
            "auth" => "\"api-key\"",
            "pinentry" => "\"pinentry\"",
            "server_url" => "\"https://vault.example.org\"",
            "email" => "\"me@example.org\"",
            _ => "5",
        }
    }

    #[test]
    fn every_registry_key_is_accepted_where_the_registry_puts_it() {
        let top: String = keys_in("top").iter().map(|k| format!("{k} = {}\n", sample(k))).collect();
        let profile: String = keys_in("profile").iter().map(|k| format!("{k} = {}\n", sample(k))).collect();
        let s = resolve(&doc(&format!("{top}[profiles.personal]\n{profile}"))).unwrap();
        assert_eq!(s.account.unwrap().profile, "personal");
    }

    #[test]
    fn a_registry_key_outside_its_place_is_an_error() {
        for key in keys_in("profile").iter().filter(|k| !keys_in("top").contains(k)) {
            let e = err(&format!("default = \"personal\"\n{key} = {}\n{ACCOUNT}", sample(key)));
            assert!(e.contains(&format!("`{key}`")) && e.contains("top level"), "{key}: {e}");
        }
        for key in keys_in("top").iter().filter(|k| !keys_in("profile").contains(k)) {
            let e = err(&format!("default = \"personal\"\n{ACCOUNT}{key} = {}\n", sample(key)));
            assert!(e.contains(&format!("`{key}`")) && e.contains("every profile"), "{key}: {e}");
        }
    }

    // ---- resolution -------------------------------------------------------

    #[test]
    fn settings_come_from_the_profile_then_the_top_level_then_the_default() {
        let base = format!("default = \"personal\"\n{ACCOUNT}");
        let s = resolve(&doc(&base)).unwrap();
        assert_eq!(s.lock_timeout_minutes, 60);
        assert_eq!(s.sync_interval_seconds, 300);
        assert_eq!(s.pinentry, "pinentry");

        let top = format!("lock_timeout_minutes = 30\nsync_interval_seconds = 120\npinentry = \"pinentry-qt\"\n{base}");
        let s = resolve(&doc(&top)).unwrap();
        assert_eq!((s.lock_timeout_minutes, s.sync_interval_seconds, s.pinentry.as_str()), (30, 120, "pinentry-qt"));

        let over = format!("{top}lock_timeout_minutes = 5\npinentry = \"/usr/bin/pinentry-gnome3\"\n");
        let s = resolve(&doc(&over)).unwrap();
        assert_eq!(s.lock_timeout_minutes, 5);
        assert_eq!(s.sync_interval_seconds, 120, "not overridden: from the top level");
        assert_eq!(s.pinentry, "/usr/bin/pinentry-gnome3");
    }

    #[test]
    fn the_example_config_is_valid() {
        let s = resolve(&doc(include_str!("../contrib/config.example.toml"))).unwrap();
        assert_eq!(s.account.unwrap().profile, "personal");
        assert_eq!((s.lock_timeout_minutes, s.folder.as_str()), (60, DEFAULT_FOLDER));
    }

    #[test]
    fn bwss_serves_its_own_profile_or_the_default() {
        let two = format!(
            "default = \"personal\"\n{ACCOUNT}[profiles.work]\nserver_url = \"https://vault.example.corp\"\nemail = \"me@example.corp\"\nlock_timeout_minutes = 15\n"
        );
        let s = resolve(&doc(&two)).unwrap();
        let a = s.account.unwrap();
        assert_eq!((a.profile.as_str(), a.email.as_str()), ("personal", "me@example.org"));
        assert_eq!(s.lock_timeout_minutes, 60, "work's override is not ours");

        let s = resolve(&doc(&format!("{two}[bwss]\nprofile = \"work\"\nfolder = \"keyring\"\n"))).unwrap();
        let a = s.account.clone().unwrap();
        assert_eq!((a.profile.as_str(), a.server_url.as_str()), ("work", "https://vault.example.corp"));
        assert_eq!(s.lock_timeout_minutes, 15);
        assert_eq!(s.folder, "keyring");
        assert_eq!(s.backend, BackendKind::Bitwarden);
    }

    #[test]
    fn the_bwss_section_has_defaults_and_a_memory_backend() {
        let s = resolve(&doc(&format!("default = \"personal\"\n{ACCOUNT}"))).unwrap();
        assert_eq!((s.backend, s.folder.as_str()), (BackendKind::Bitwarden, DEFAULT_FOLDER));
        // The memory backend needs no account.
        let s = resolve(&doc("[bwss]\nbackend = \"memory\"\nmemory_password = \"open\"\n")).unwrap();
        assert_eq!((s.backend, s.account, s.memory_password.as_str()), (BackendKind::Memory, None, "open"));
    }

    #[test]
    fn the_bitwarden_backend_needs_a_defined_profile_with_an_account() {
        assert!(err("").contains("`default`"), "{}", err(""));
        assert!(err("default = \"nope\"\n").contains("[profiles.nope]"));
        let e = err("default = \"p\"\n[profiles.p]\nemail = \"me@example.org\"\n");
        assert!(e.contains("`server_url`") && e.contains("[profiles.p]"), "{e}");
        let e = err("default = \"p\"\n[profiles.p]\nserver_url = \"https://x.org\"\n");
        assert!(e.contains("`email`"), "{e}");
        for bad in ["..", ".", "a/b", ""] {
            let e =
                err(&format!("default = {bad:?}\n[profiles.{bad:?}]\nserver_url = \"https://x.org\"\nemail = \"e\"\n"));
            assert!(e.contains("profile name"), "{bad}: {e}");
        }
    }

    #[test]
    fn unknown_keys_are_errors_at_the_top_in_the_profile_and_in_bwss() {
        let base = format!("default = \"personal\"\n{ACCOUNT}");
        let e = err(&format!("idle_lock_minutes = 5\n{base}"));
        assert!(e.contains("unknown key `idle_lock_minutes`") && e.contains("top level"), "{e}");
        let e = err(&format!("{base}prompter = \"pinentry\"\n"));
        assert!(e.contains("unknown key `prompter`") && e.contains("[profiles.personal]"), "{e}");
        let e = err(&format!("{base}[bwss]\nfolders = \"x\"\n"));
        assert!(e.contains("unknown key `folders`") && e.contains("[bwss]"), "{e}");
        // `profiles` and `bwss` must be tables.
        assert!(err("profiles = 3\n").contains("`profiles`"));
        assert!(err("bwss = 3\n").contains("`bwss`"));
        assert!(err(&format!("{base}[profiles]\nstray = 1\n")).contains("profiles.stray"));
    }

    #[test]
    fn only_the_served_profile_and_bwss_are_validated() {
        let other = "[profiles.other]\nserver_url = 1\nmystery = true\n";
        let tools =
            "[ssh_agent]\nprofiles = [\"personal\"]\n[obsidian]\nanything = 1\n[some_future_tool.deep]\nx = 1\n";
        let s = resolve(&doc(&format!("default = \"personal\"\n{ACCOUNT}{other}{tools}[[future]]\nx = 1\n"))).unwrap();
        assert_eq!(s.account.unwrap().profile, "personal");
        // A bare array is not a table: the top level holds registry scalars only.
        assert!(err(&format!("future = [1]\ndefault = \"personal\"\n{ACCOUNT}")).contains("unknown key `future`"));
    }

    #[test]
    fn values_must_have_the_right_type() {
        let base = format!("default = \"personal\"\n{ACCOUNT}");
        assert!(err(&format!("lock_timeout_minutes = \"5\"\n{base}")).contains("`lock_timeout_minutes`"));
        assert!(err(&format!("lock_timeout_minutes = -1\n{base}")).contains("`lock_timeout_minutes`"));
        assert!(err(&format!("sync_interval_seconds = 1.5\n{base}")).contains("`sync_interval_seconds`"));
        assert!(err(&format!("pinentry = 3\n{base}")).contains("`pinentry`"));
        assert!(err(&format!("pinentry = \"\"\n{base}")).contains("`pinentry`"));
        assert!(err(&format!("clipboard_clear_seconds = \"x\"\n{base}")).contains("`clipboard_clear_seconds`"));
        assert!(err(&format!("auth = \"token\"\n{base}")).contains("`auth`"));
        assert!(err("default = 3\n").contains("`default`"));
        assert!(err(&format!("{base}[bwss]\nbackend = \"vault\"\n")).contains("`backend`"));
        assert!(err(&format!("{base}[bwss]\nfolder = 1\n")).contains("`folder`"));
    }

    #[test]
    fn bwss_logs_in_with_an_api_key_only() {
        let base = format!("default = \"personal\"\n{ACCOUNT}");
        let e = err(&format!("auth = \"password\"\n{base}"));
        assert!(e.contains("auth = \"password\"") && e.contains("api-key"), "the method is named: {e}");
        // Another profile's password login is not bwss's business.
        let ok = format!("{base}[profiles.cli]\nserver_url = \"https://x.org\"\nemail = \"e\"\nauth = \"password\"\n");
        assert!(resolve(&doc(&ok)).is_ok());
    }

    #[test]
    fn an_acl_key_where_bwss_reads_is_an_error() {
        let base = format!("default = \"personal\"\n{ACCOUNT}");
        for (text, at) in [
            (format!("acl = \"off\"\n{base}"), "the top level"),
            (format!("{base}acl = \"off\"\n"), "[profiles.personal]"),
            (format!("{base}[bwss]\nacl = \"off\"\n"), "[bwss]"),
        ] {
            let e = err(&text);
            assert!(e.contains("`acl`") && e.contains(at) && e.contains("bwss acl off"), "{text}: {e}");
        }
    }

    #[test]
    fn the_file_cannot_put_derived_attributes_in_the_locked_index() {
        let base = format!("default = \"personal\"\n{ACCOUNT}");
        for value in ["true", "false"] {
            let e = err(&format!("{base}[bwss]\nindex_derived_attributes = {value}\n"));
            assert!(
                e.contains("`index_derived_attributes` in [bwss]") && e.contains("bwss index derived on"),
                "{value}: {e}"
            );
            assert!(!e.contains("unknown key"), "{e}");
        }
    }

    #[test]
    fn an_acl_key_in_another_tools_table_is_not_bwss_business() {
        let base = format!("default = \"personal\"\n{ACCOUNT}");
        for text in [
            format!("{base}[obsidian]\nacl = \"off\"\n"),
            format!("{base}[profiles.other]\nacl = \"off\"\n"),
            format!("{base}[[tools]]\nacl = \"off\"\n"),
            format!("{base}[some_tool.nested]\nacl = \"off\"\n"),
        ] {
            assert!(resolve(&doc(&text)).is_ok(), "{text}");
        }
    }

    #[test]
    fn root_is_refused() {
        let e = format!("{:#}", refuse_root(&User { uid: 0, groups: None }).unwrap_err());
        assert!(e.contains("root"), "{e}");
        assert!(refuse_root(&User { uid: 1000, groups: Some(vec![]) }).is_ok());
    }

    // ---- paths and device state --------------------------------------------

    fn paths_in(home: &Path) -> Paths {
        let home = home.as_os_str().to_owned();
        Paths::with(move |v| (v == "HOME").then(|| home.clone()))
    }

    #[test]
    fn paths_follow_the_dybw_layout() {
        let p = Paths::with(|v| match v {
            "HOME" => Some("/home/u".into()),
            "XDG_STATE_HOME" => Some("/st".into()),
            "XDG_CONFIG_HOME" => Some("relative/ignored".into()),
            _ => None,
        });
        assert_eq!(p.config, Path::new("/home/u/.config/dybw/config.toml"));
        assert_eq!(p.legacy_config, Path::new("/home/u/.config/bwss/config.toml"));
        assert_eq!(p.credentials("work"), Path::new("/st/dybw/profiles/work/credentials"));
        assert_eq!(p.device_id("work"), Path::new("/st/dybw/profiles/work/devices/bwss"));
        assert_eq!(p.acl_off(), Path::new("/st/dybw/tools/bwss/acl-off"));
        assert_eq!(p.index_derived(), Path::new("/st/dybw/tools/bwss/index-derived"));
        assert_eq!(p.locked_index(), Path::new("/home/u/.cache/bwss/locked-index.json"));
        assert_eq!(p.cache, Path::new("/home/u/.cache/bwss"));
        assert_eq!(p.state, Path::new("/st/bwss"));
    }

    #[test]
    fn derived_attributes_in_the_index_are_device_state() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = paths_in(dir.path());
        assert!(!flag_set(&p.index_derived()));
        set_index_derived(&p, true).unwrap();
        assert!(flag_set(&p.index_derived()));
        assert_eq!(std::fs::metadata(p.index_derived()).unwrap().permissions().mode() & 0o777, 0o600);
        set_index_derived(&p, true).unwrap();
        set_index_derived(&p, false).unwrap();
        assert!(!flag_set(&p.index_derived()));
        set_index_derived(&p, false).unwrap();
        // The ACL flag is another file.
        set_index_derived(&p, true).unwrap();
        assert_eq!(acl_mode(&p), AclMode::Prompt);
    }

    #[test]
    fn acl_off_is_device_state() {
        let home = tempfile::tempdir().unwrap();
        let p = paths_in(home.path());
        assert_eq!(acl_mode(&p), AclMode::Prompt);
        set_acl_off(&p, true).unwrap();
        assert_eq!(acl_mode(&p), AclMode::Off);
        set_acl_off(&p, true).unwrap();
        set_acl_off(&p, false).unwrap();
        assert_eq!(acl_mode(&p), AclMode::Prompt);
        set_acl_off(&p, false).unwrap();
    }

    #[test]
    fn an_old_bwss_config_without_a_bwss_section_asks_for_a_migration() {
        let home = tempfile::tempdir().unwrap();
        let p = paths_in(home.path());
        std::fs::create_dir_all(p.legacy_config.parent().unwrap()).unwrap();
        std::fs::write(&p.legacy_config, "email = \"me@example.org\"\n").unwrap();
        let e = format!("{:#}", load_settings(&p).unwrap_err());
        assert!(e.contains("bwss config migrate"), "{e}");

        std::fs::create_dir_all(p.config.parent().unwrap()).unwrap();
        std::fs::write(&p.config, format!("default = \"personal\"\n{ACCOUNT}")).unwrap();
        assert!(format!("{:#}", load_settings(&p).unwrap_err()).contains("bwss config migrate"));

        std::fs::write(&p.config, format!("default = \"personal\"\n{ACCOUNT}[bwss]\n")).unwrap();
        assert_eq!(load_settings(&p).unwrap().account.unwrap().profile, "personal");
    }

    #[test]
    fn a_missing_file_reads_as_empty_and_a_broken_one_names_itself() {
        let home = tempfile::tempdir().unwrap();
        let p = paths_in(home.path());
        assert!(read_doc(&p.config).unwrap().is_none());
        assert!(format!("{:#}", load_settings(&p).unwrap_err()).contains("`default`"));
        std::fs::create_dir_all(p.config.parent().unwrap()).unwrap();
        std::fs::write(&p.config, "default = \n").unwrap();
        let e = format!("{:#}", load_settings(&p).unwrap_err());
        assert!(e.contains("config.toml"), "{e}");
        std::fs::write(&p.config, "acl = \"off\"\n").unwrap();
        let e = format!("{:#}", load_settings(&p).unwrap_err());
        assert!(e.contains("config.toml") && e.contains("`acl`"), "{e}");
        std::fs::remove_file(&p.config).unwrap();
        std::fs::create_dir(&p.config).unwrap();
        let e = format!("{:#}", load_settings(&p).unwrap_err());
        assert!(e.contains("config.toml"), "{e}");
    }

    // ---- pinentry -----------------------------------------------------------

    #[cfg(unix)]
    mod pinentry {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        use super::*;

        /// A tree owned by "someone else": `me` is a uid that is not ours, so
        /// nothing in it is writable unless a write bit says so.
        struct Fixture {
            _dir: tempfile::TempDir,
            root: PathBuf,
            bin: PathBuf,
            other: PathBuf,
            me: User,
        }

        fn chmod(path: &Path, mode: u32) {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }

        fn fixture() -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap().join("prefix");
            let bin = root.join("bin");
            let other = root.join("other");
            for d in [&bin, &other] {
                std::fs::create_dir_all(d).unwrap();
                for name in ["pinentry", "pinentry-qt"] {
                    let f = d.join(name);
                    std::fs::write(&f, "#!/bin/sh\n").unwrap();
                    chmod(&f, 0o755);
                }
                chmod(d, 0o755);
            }
            chmod(&root, 0o755);
            let owner = std::fs::metadata(&bin).unwrap().uid();
            let me = User { uid: owner.wrapping_add(1).max(1), groups: Some(vec![]) };
            Fixture { _dir: dir, root, bin, other, me }
        }

        fn trust(f: &Fixture, user: User) -> Trust {
            Trust { search: Some(std::env::join_paths([&f.other, &f.bin]).unwrap()), user, exe: None, home: None }
        }

        fn refusal(t: &Trust, pinentry: &Path) -> String {
            format!("{:#}", t.check(pinentry.to_str().unwrap()).unwrap_err())
        }

        #[test]
        fn a_program_nobody_but_its_owner_can_write_is_accepted_resolved() {
            let f = fixture();
            let t = Trust { search: Some(f.bin.clone().into_os_string()), ..trust(&f, f.me.clone()) };
            assert_eq!(t.check("pinentry-qt").unwrap(), (f.bin.join("pinentry-qt"), PinentryRule::NotWritable));
            // A link is followed: the program run is the one checked.
            std::os::unix::fs::symlink(f.other.join("pinentry"), f.bin.join("link")).unwrap();
            assert_eq!(t.check(f.bin.join("link").to_str().unwrap()).unwrap().0, f.other.join("pinentry"));
            assert!(format!("{:#}", t.check("bin/pinentry").unwrap_err()).contains("absolute"));
            assert!(format!("{:#}", t.check("pinentry-none").unwrap_err()).contains("not found"));
            assert!(t.check("").is_err());
            assert!(t.check(f.bin.join("missing").to_str().unwrap()).is_err());
            let none = Trust { search: None, ..trust(&f, f.me.clone()) };
            assert!(format!("{:#}", none.check("pinentry").unwrap_err()).contains("not found"));
        }

        #[test]
        fn a_link_into_a_writable_directory_is_refused() {
            let f = fixture();
            chmod(&f.other, 0o777);
            std::os::unix::fs::symlink(f.other.join("pinentry"), f.bin.join("link")).unwrap();
            let e = refusal(&trust(&f, f.me.clone()), &f.bin.join("link"));
            assert!(e.contains("writable") && e.contains(&f.other.display().to_string()), "{e}");
        }

        #[test]
        fn a_program_the_user_can_write_is_refused() {
            let f = fixture();
            let p = f.bin.join("pinentry");
            // Owned by the user: refused even without a write bit.
            let owner = User { uid: std::fs::metadata(&p).unwrap().uid(), groups: Some(vec![]) };
            assert!(refusal(&trust(&f, owner), &p).contains("writable"));

            let t = trust(&f, f.me.clone());
            chmod(&p, 0o757);
            assert!(refusal(&t, &p).contains("writable"));
            chmod(&p, 0o775);
            let gid = std::fs::metadata(&p).unwrap().gid();
            assert!(trust(&f, User { groups: Some(vec![gid]), ..f.me.clone() }).check(p.to_str().unwrap()).is_err());
            assert!(t.check(p.to_str().unwrap()).is_ok(), "group-writable, but not our group");
            chmod(&p, 0o755);

            chmod(&f.bin, 0o777);
            let e = refusal(&t, &p);
            assert!(e.contains("writable") && e.contains(&f.bin.display().to_string()), "{e}");
            chmod(&f.bin, 0o755);
            assert!(t.check(p.to_str().unwrap()).is_ok());
        }

        #[test]
        fn every_directory_above_the_program_counts() {
            let f = fixture();
            let t = trust(&f, f.me.clone());
            let p = f.bin.join("pinentry");
            chmod(&f.root, 0o777);
            let e = refusal(&t, &p);
            assert!(e.contains(&format!("{} is writable", f.root.display())), "{e}");
            // A sticky directory (like /tmp) owned by someone else only lets
            // the user replace what the user owns.
            chmod(&f.root, 0o1777);
            assert_eq!(t.check(p.to_str().unwrap()).unwrap().1, PinentryRule::NotWritable);
            let owner = User { uid: std::fs::metadata(&f.bin).unwrap().uid(), groups: Some(vec![]) };
            chmod(&f.bin, 0o555);
            chmod(&p, 0o555);
            assert!(trust(&f, owner).check(p.to_str().unwrap()).is_err(), "the owner's own entry");
            chmod(&f.root, 0o755);
            chmod(&f.bin, 0o755);
        }

        /// A Homebrew-like prefix the user can write, with bwss in a keg.
        struct Brew {
            f: Fixture,
            prefix: PathBuf,
            exe: PathBuf,
            home: PathBuf,
        }

        fn brew() -> Brew {
            let f = fixture();
            let prefix = f.root.join("brew");
            let exe = prefix.join("Cellar/bwss/1.0/bin/bwss");
            let pin = prefix.join("Cellar/pinentry-mac/1.4/bin/pinentry-mac");
            for file in [&exe, &pin, &prefix.join("share/pinentry"), &prefix.join("opt/pe/bin/pinentry")] {
                std::fs::create_dir_all(file.parent().unwrap()).unwrap();
                std::fs::write(file, "#!/bin/sh\n").unwrap();
                chmod(file, 0o757); // writable by everyone, so by `me`
            }
            std::fs::create_dir_all(prefix.join("bin")).unwrap();
            std::os::unix::fs::symlink(&pin, prefix.join("bin/pinentry-mac")).unwrap();
            chmod(&prefix.join("bin"), 0o777);
            let home = f.root.join("home");
            std::fs::create_dir(&home).unwrap();
            Brew { f, prefix, exe, home }
        }

        fn brew_trust(b: &Brew) -> Trust {
            Trust { exe: Some(b.exe.clone()), home: Some(b.home.clone()), ..trust(&b.f, b.f.me.clone()) }
        }

        fn brew_check(t: &Trust, file: &Path) -> Result<PinentryRule, String> {
            t.check(file.to_str().unwrap()).map(|(_, rule)| rule).map_err(|e| format!("{e:#}"))
        }

        #[test]
        fn a_homebrew_pinentry_beside_a_homebrew_bwss_is_trusted() {
            let b = brew();
            let t = brew_trust(&b);
            let rule = PinentryRule::SamePrefix(b.prefix.clone());
            assert_eq!(brew_check(&t, &b.prefix.join("bin/pinentry-mac")), Ok(rule.clone()), "a link into a keg");
            assert_eq!(brew_check(&t, &b.prefix.join("opt/pe/bin/pinentry")), Ok(rule.clone()));
            assert!(rule.to_string().contains("prefix"));
            assert!(PinentryRule::NotWritable.to_string().contains("not writable"));
            // Without the rule, the same file is refused.
            let e = brew_check(&trust(&b.f, b.f.me.clone()), &b.prefix.join("bin/pinentry-mac")).unwrap_err();
            assert!(e.contains("writable"), "{e}");
        }

        #[test]
        fn only_the_prefix_program_directories_count() {
            let b = brew();
            let e = brew_check(&brew_trust(&b), &b.prefix.join("share/pinentry")).unwrap_err();
            assert!(e.contains("not in a program directory"), "{e}");
        }

        #[test]
        fn a_bwss_the_user_cannot_write_never_uses_the_prefix_rule() {
            let b = brew();
            chmod(&b.exe, 0o755);
            let e = brew_check(&brew_trust(&b), &b.prefix.join("bin/pinentry-mac")).unwrap_err();
            assert!(e.contains("bwss itself") && e.contains("not writable"), "{e}");
            let unknown = Trust { exe: None, ..brew_trust(&b) };
            assert!(brew_check(&unknown, &b.prefix.join("bin/pinentry-mac")).unwrap_err().contains("unknown"));
        }

        #[test]
        fn no_prefix_in_or_above_home_is_trusted() {
            let b = brew();
            // `cargo install`: ~/.cargo/bin/bwss and a pinentry beside it.
            let cargo = b.home.join(".cargo/bin");
            std::fs::create_dir_all(&cargo).unwrap();
            for name in ["bwss", "pinentry"] {
                std::fs::write(cargo.join(name), "#!/bin/sh\n").unwrap();
                chmod(&cargo.join(name), 0o757);
            }
            let t = Trust { exe: Some(cargo.join("bwss")), ..brew_trust(&b) };
            let e = brew_check(&t, &cargo.join("pinentry")).unwrap_err();
            assert!(e.contains("inside your home"), "{e}");

            let at_home = Trust { home: Some(b.prefix.clone()), ..brew_trust(&b) };
            assert!(brew_check(&at_home, &b.prefix.join("bin/pinentry-mac")).unwrap_err().contains("is your home"));
            let above = Trust { home: Some(b.prefix.join("users/me")), ..brew_trust(&b) };
            assert!(brew_check(&above, &b.prefix.join("bin/pinentry-mac")).unwrap_err().contains("contains your home"));
        }

        #[test]
        fn the_prefix_is_the_keg_root_or_the_grandparent() {
            let p = |s: &str| install_prefix(Path::new(s));
            assert_eq!(p("/opt/homebrew/Cellar/bwss/1.0/bin/bwss"), Some(PathBuf::from("/opt/homebrew")));
            assert_eq!(
                p("/home/linuxbrew/.linuxbrew/Cellar/bwss/1/bin/bwss"),
                Some(PathBuf::from("/home/linuxbrew/.linuxbrew"))
            );
            assert_eq!(p("/usr/local/bin/bwss"), Some(PathBuf::from("/usr/local")));
            assert_eq!(p("/bin/bwss"), Some(PathBuf::from("/")));
            assert_eq!(p("/bwss"), None);

            let home = Some(Path::new("/home/me"));
            assert!(prefix_problem(Path::new("/"), home).unwrap().contains("`/`"));
            assert!(prefix_problem(Path::new("/opt/homebrew"), None).unwrap().contains("home"));
            assert_eq!(prefix_problem(Path::new("/home/linuxbrew/.linuxbrew"), home), None);
            assert_eq!(prefix_problem(Path::new("/opt/homebrew"), home), None);

            let prefix = Path::new("/opt/homebrew");
            for ok in ["bin/x", "sbin/x", "opt/pe/bin/x", "Cellar/pe/1.0/bin/x"] {
                assert!(in_prefix_bin(prefix, &prefix.join(ok)), "{ok}");
            }
            for no in ["x", "share/x", "bin/sub/x", "opt/bin/x", "Cellar/pe/bin/x", "lib/pe/bin/x"] {
                assert!(!in_prefix_bin(prefix, &prefix.join(no)), "{no}");
            }
            assert!(!in_prefix_bin(prefix, Path::new("/usr/bin/x")));
        }

        #[test]
        fn the_rule_is_checked_again_before_each_use() {
            let f = fixture();
            let t = trust(&f, f.me.clone());
            let (p, _) = t.check(f.bin.join("pinentry").to_str().unwrap()).unwrap();
            assert_eq!(t.verify(&p).unwrap(), PinentryRule::NotWritable);
            chmod(&p, 0o757);
            assert!(format!("{:#}", t.verify(&p).unwrap_err()).contains("writable"));
            chmod(&p, 0o755);
            // Replaced by a link since it was checked: refused.
            std::fs::remove_file(&p).unwrap();
            std::os::unix::fs::symlink(f.other.join("pinentry"), &p).unwrap();
            assert!(format!("{:#}", t.verify(&p).unwrap_err()).contains("resolves"));
            std::fs::create_dir(f.bin.join("dir")).unwrap();
            assert!(format!("{:#}", t.verify(&f.bin.join("dir")).unwrap_err()).contains("not a program"));
        }

        #[test]
        fn a_sticky_directory_shields_only_others_entries_in_others_directories() {
            let me = User { uid: 1000, groups: Some(vec![]) };
            assert!(sticky_shields(0o1777, 0, 0, &me), "/tmp/<root's dir>");
            assert!(!sticky_shields(0o1777, 0, 1000, &me), "our own entry");
            assert!(!sticky_shields(0o1777, 1000, 0, &me), "our own sticky directory");
            assert!(!sticky_shields(0o0777, 0, 0, &me), "not sticky");
            assert!(!sticky_shields(0o1775, 0, 0, &me), "sticky but not world-writable");
            assert!(!sticky_shields(0o1777, 0, 0, &User { uid: 0, groups: None }), "root");
        }

        #[test]
        fn the_system_trust_uses_this_user_exe_and_home() {
            let t = Trust::system().unwrap();
            assert_eq!(t.user, User::current().unwrap());
            assert_eq!(t.exe, Some(std::env::current_exe().unwrap().canonicalize().unwrap()));
            let home = std::env::var_os("HOME").map(PathBuf::from).and_then(|h| h.canonicalize().ok());
            assert_eq!(t.home, home);
        }

        #[test]
        fn load_checks_the_pinentry_and_reads_the_acl_state() {
            let f = fixture();
            let home = tempfile::tempdir().unwrap();
            let p = paths_in(home.path());
            std::fs::create_dir_all(p.config.parent().unwrap()).unwrap();
            let pin = f.bin.join("pinentry");
            std::fs::write(&p.config, format!("pinentry = {:?}\ndefault = \"personal\"\n{ACCOUNT}", pin)).unwrap();
            let c = load(&p, &trust(&f, f.me.clone())).unwrap();
            assert_eq!(c.pinentry, pin.to_str().unwrap());
            assert_eq!((c.profile.as_deref(), c.email.as_str()), (Some("personal"), "me@example.org"));
            assert_eq!(c.server_url, "https://vault.example.org");
            assert_eq!((c.acl, c.lock_timeout_minutes), (AclMode::Prompt, 60));
            set_acl_off(&p, true).unwrap();
            assert_eq!(load(&p, &trust(&f, f.me.clone())).unwrap().acl, AclMode::Off);

            chmod(&f.other, 0o777);
            std::fs::write(
                &p.config,
                format!("pinentry = {:?}\ndefault = \"personal\"\n{ACCOUNT}", f.other.join("pinentry")),
            )
            .unwrap();
            assert!(load(&p, &trust(&f, f.me.clone())).is_err());
        }
    }

    // ---- credentials --------------------------------------------------------

    #[cfg(unix)]
    mod credentials {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        use super::*;

        const ORIGIN: &str = "https://identity.example.org";

        fn creds() -> Credentials {
            Credentials {
                identity_origin: ORIGIN.into(),
                client_id: "cid".into(),
                client_secret: Zeroizing::new("csecret".into()),
            }
        }

        fn me(path: &Path) -> User {
            User { uid: std::fs::metadata(path).unwrap().uid(), groups: None }
        }

        #[test]
        fn saved_credentials_load_for_their_origin_only() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("profiles/p/credentials");
            save_credentials(&path, &creds()).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777, 0o700);
            let c = load_credentials(&path, &me(&path), ORIGIN).unwrap();
            assert_eq!((c.client_id.as_str(), c.client_secret.as_str()), ("cid", "csecret"));

            let e = format!("{:#}", load_credentials(&path, &me(&path), "https://identity.evil.example").unwrap_err());
            assert!(e.contains(ORIGIN) && e.contains("identity.evil.example") && e.contains("bwss login"), "{e}");
        }

        #[test]
        fn credentials_must_be_private_owned_and_not_a_link() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("credentials");
            assert!(
                format!("{:#}", load_credentials(&path, &User { uid: 1, groups: None }, ORIGIN).unwrap_err())
                    .contains("bwss login")
            );
            save_credentials(&path, &creds()).unwrap();
            let user = me(&path);

            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(format!("{:#}", load_credentials(&path, &user, ORIGIN).unwrap_err()).contains("chmod 600"));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

            let stranger = User { uid: user.uid.wrapping_add(1), groups: None };
            assert!(format!("{:#}", load_credentials(&path, &stranger, ORIGIN).unwrap_err()).contains("owned"));

            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(format!("{:#}", load_credentials(&link, &user, ORIGIN).unwrap_err()).contains("symbolic link"));

            let sub = dir.path().join("sub");
            std::fs::create_dir(&sub).unwrap();
            assert!(format!("{:#}", load_credentials(&sub, &user, ORIGIN).unwrap_err()).contains("regular file"));

            std::fs::write(&path, "client_id = \"no origin\"\n").unwrap();
            assert!(load_credentials(&path, &user, ORIGIN).is_err());
        }

        #[test]
        fn credentials_have_exactly_three_keys() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("credentials");
            save_credentials(&path, &creds()).unwrap();
            let user = me(&path);
            let saved: Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let mut keys: Vec<&str> = saved.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(keys, ["client_id", "client_secret", "identity_origin"]);

            let full = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, format!("{full}extra = 1\n")).unwrap();
            let e = format!("{:#}", load_credentials(&path, &user, ORIGIN).unwrap_err());
            assert!(e.contains("an unknown key") && !e.contains("extra"), "{e}");
            std::fs::write(&path, "identity_origin = \"https://identity.example.org\"\nclient_id = \"cid\"\n").unwrap();
            let e = format!("{:#}", load_credentials(&path, &user, ORIGIN).unwrap_err());
            assert!(e.contains("missing key `client_secret`"), "{e}");
        }

        #[test]
        fn a_broken_credentials_file_never_shows_its_secret() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("credentials");
            save_credentials(&path, &creds()).unwrap();
            let user = me(&path);
            for text in [
                "identity_origin = \"https://identity.example.org\"\nclient_id = \"cid\"\nclient_secret = \"s3cr3t-leak\n",
                "client_secret = 's3cr3t-leak' 'more'\n",
                "client_secret = \"s3cr3t-leak\"\nclient_secret = \"s3cr3t-leak\"\n",
                "identity_origin = 1\nclient_id = \"s3cr3t-leak\"\nclient_secret = \"x\"\n",
                "s3cr3t-leak = 1\n",
            ] {
                std::fs::write(&path, text).unwrap();
                let e = format!("{:#}", load_credentials(&path, &user, ORIGIN).unwrap_err());
                assert!(!e.contains("s3cr3t"), "{e}");
                assert!(e.contains(&path.display().to_string()), "{e}");
            }
            std::fs::write(&path, "client_secret = \"s3cr3t-leak\n").unwrap();
            let e = format!("{:#}", load_credentials(&path, &user, ORIGIN).unwrap_err());
            assert!(e.contains("line 1"), "the position is kept: {e}");
        }
    }
}
