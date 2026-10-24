//! `bwss config migrate`: moves `~/.config/bwss/config.toml` into the shared
//! dybw file (ADR 0008, "Migration").
//!
//! The dybw file is edited as text, so its comments and layout survive:
//! sections are appended and overrides are inserted under a profile's
//! header. The result is parsed and resolved before anything is written.
//! Old files are renamed `*.migrated`, never deleted.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;
use toml::{Table, Value};
use zeroize::Zeroizing;

use crate::bw::api::identity_origin;
use crate::config::{
    self, BackendKind, Credentials, DEFAULT_FOLDER, DEFAULT_LOCK_TIMEOUT_MINUTES, DEFAULT_MEMORY_PASSWORD,
    DEFAULT_PINENTRY, Paths, Trust,
};

/// The profile `bwss config migrate` creates when none has the account.
const NEW_PROFILE: &str = "bwss";

#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum LegacyAcl {
    #[default]
    Prompt,
    Off,
}

/// `~/.config/bwss/config.toml` before ADR 0008.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Legacy {
    backend: BackendKind,
    server_url: String,
    email: String,
    folder: String,
    prompter: Option<String>,
    acl: LegacyAcl,
    idle_lock_minutes: u64,
    sync_interval_seconds: u64,
    memory_password: String,
}

impl Default for Legacy {
    fn default() -> Self {
        Legacy {
            backend: BackendKind::Bitwarden,
            server_url: "https://vault.bitwarden.com".into(),
            email: String::new(),
            folder: DEFAULT_FOLDER.into(),
            prompter: None,
            acl: LegacyAcl::Prompt,
            idle_lock_minutes: 0,
            sync_interval_seconds: config::DEFAULT_SYNC_INTERVAL_SECONDS,
            memory_password: DEFAULT_MEMORY_PASSWORD.into(),
        }
    }
}

/// `~/.config/bwss/credentials.toml` before ADR 0008.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCredentials {
    client_id: String,
    client_secret: Zeroizing<String>,
}

fn read_optional(path: &Path) -> anyhow::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::new(e).context(path.display().to_string())),
    }
}

fn same_account(profile: &Table, legacy: &Legacy) -> bool {
    let server = |s: &str| s.trim().trim_end_matches('/').to_ascii_lowercase();
    let get = |k: &str| profile.get(k).and_then(Value::as_str).unwrap_or_default();
    server(get("server_url")) == server(&legacy.server_url) && get("email").eq_ignore_ascii_case(legacy.email.trim())
}

/// The index of the line that opens `[profiles.<name>]`, in any spelling.
fn header_line(lines: &[&str], name: &str) -> Option<usize> {
    lines.iter().position(|line| {
        let t = line.trim_start();
        if !t.starts_with('[') || t.starts_with("[[") {
            return false;
        }
        let Ok(header) = toml::from_str::<Table>(line) else { return false };
        let profiles = header.get("profiles").and_then(Value::as_table);
        header.len() == 1 && profiles.is_some_and(|p| p.len() == 1 && p.get(name).is_some())
    })
}

/// `path`, or where it points when it is a link (a dotfile manager's). A
/// link to nothing is refused rather than replaced by a file.
fn real_path(path: &Path) -> anyhow::Result<PathBuf> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(path).map_err(|e| {
            let to = std::fs::read_link(path).unwrap_or_default();
            anyhow::anyhow!(
                "{} is a link to {} that cannot be followed ({e}); fix or remove the link",
                path.display(),
                to.display()
            )
        }),
        _ => Ok(path.to_owned()),
    }
}

/// The permission bits of `path`, or 0600 for a new file.
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).map_or(0o600, |m| m.permissions().mode() & 0o7777)
}

/// Renames `path` to the first free `<path>.migrated[.N]`.
fn set_aside(path: &Path) -> anyhow::Result<PathBuf> {
    let mut target = PathBuf::from(format!("{}.migrated", path.display()));
    let mut n = 2;
    while std::fs::symlink_metadata(&target).is_ok() {
        target = PathBuf::from(format!("{}.migrated.{n}", path.display()));
        n += 1;
    }
    std::fs::rename(path, &target).with_context(|| format!("renaming {}", path.display()))?;
    Ok(target)
}

/// Runs the migration and returns what it did, one line per step.
/// `confirm_acl_off` asks the user whether `acl = "off"` may become device
/// state.
pub fn migrate(
    paths: &Paths,
    trust: &Trust,
    confirm_acl_off: &mut dyn FnMut() -> anyhow::Result<bool>,
) -> anyhow::Result<Vec<String>> {
    let old = &paths.legacy_config;
    let Some(legacy_text) = read_optional(old)? else {
        bail!("nothing to migrate: {} does not exist", old.display());
    };
    let legacy: Legacy = toml::from_str(&legacy_text).with_context(|| old.display().to_string())?;
    let target = real_path(&paths.config)?;
    let original = read_optional(&target)?.unwrap_or_default();
    let doc: Table = toml::from_str(&original).with_context(|| paths.config.display().to_string())?;
    if doc.contains_key("bwss") {
        bail!(
            "{} already has a [bwss] section; check it, then rename {} yourself",
            paths.config.display(),
            old.display()
        );
    }
    if let Some(prompter) = &legacy.prompter {
        trust.check(prompter).with_context(|| format!("`prompter` in {}", old.display()))?;
    }
    if legacy.backend == BackendKind::Bitwarden && legacy.email.trim().is_empty() {
        bail!("{} has no `email`, so there is no account to move", old.display());
    }

    let mut report = Vec::new();
    let mut lines: Vec<&str> = original.split_inclusive('\n').collect();
    let profiles = doc.get("profiles").and_then(Value::as_table);
    // Where bwss's settings resolve from: (profile name, its table, whether it is new).
    let profile = if legacy.email.trim().is_empty() {
        None
    } else if let Some((name, table)) =
        profiles.into_iter().flatten().find(|(_, p)| p.as_table().is_some_and(|p| same_account(p, &legacy)))
    {
        report.push(format!("bwss serves the existing profile {name:?}, which has the same account"));
        Some((name.clone(), table.as_table(), false))
    } else if profiles.is_some_and(|p| p.contains_key(NEW_PROFILE)) {
        bail!(
            "[profiles.{NEW_PROFILE}] in {} is another account; rename it, or point it at {} on {}, and run again",
            paths.config.display(),
            legacy.email,
            legacy.server_url
        );
    } else {
        report.push(format!("added [profiles.{NEW_PROFILE}] for {} on {}", legacy.email, legacy.server_url));
        Some((NEW_PROFILE.to_owned(), None, true))
    };

    // Overrides: set in the profile, unless it already sets the key. Without
    // a profile, the top level plays its part.
    let mut wanted = Vec::new();
    if legacy.idle_lock_minutes != 0 {
        let minutes = i64::try_from(legacy.idle_lock_minutes).context("`idle_lock_minutes` is too large")?;
        let default = i64::try_from(DEFAULT_LOCK_TIMEOUT_MINUTES).unwrap_or(i64::MAX);
        wanted.push(("lock_timeout_minutes", Value::Integer(minutes), Value::Integer(default)));
    }
    if let Some(prompter) = &legacy.prompter {
        wanted.push(("pinentry", Value::String(prompter.clone()), Value::String(DEFAULT_PINENTRY.into())));
    }
    let (own, at) = match &profile {
        Some((name, table, _)) => (*table, format!("[profiles.{name}]")),
        None => (Some(&doc), "the top level".to_owned()),
    };
    let mut overrides = Vec::new();
    for (key, value, default) in wanted {
        if let Some(set) = own.and_then(|t| t.get(key)) {
            if *set != value {
                report.push(format!("kept {key} = {set} of {at}; the old config had {value}"));
            }
            continue;
        }
        let shared = if profile.is_some() { doc.get(key) } else { None };
        if *shared.unwrap_or(&default) != value {
            overrides.push(format!("{key} = {value}\n"));
            report.push(format!("set {key} = {value} in {at}"));
        }
    }
    if legacy.sync_interval_seconds != config::DEFAULT_SYNC_INTERVAL_SECONDS {
        report.push(format!(
            "sync_interval_seconds = {} was not carried over; set it in {} if you need it",
            legacy.sync_interval_seconds,
            paths.config.display()
        ));
    }

    let mut text = String::new();
    match &profile {
        Some((_, _, true)) | None => {
            if profile.is_none() {
                text.extend(overrides.iter().map(String::as_str));
            }
            text.push_str(&original);
        }
        Some((name, _, false)) => {
            if !overrides.is_empty() {
                let Some(at_line) = header_line(&lines, name) else {
                    bail!(
                        "cannot find the [profiles.{name}] header in {}: add {} there yourself and run again",
                        paths.config.display(),
                        overrides.concat().trim_end().replace('\n', ", ")
                    );
                };
                let tail = lines.split_off(at_line + 1);
                lines.extend(overrides.iter().map(String::as_str));
                lines.extend(tail);
            }
            text.push_str(&lines.concat());
        }
    }
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    let mut section = |header: String, body: Vec<String>| {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&header);
        text.extend(body);
    };
    if let Some((name, _, true)) = &profile {
        let mut body = vec![
            format!("server_url = {}\n", Value::String(legacy.server_url.clone())),
            format!("email = {}\n", Value::String(legacy.email.trim().to_owned())),
        ];
        body.extend(overrides.iter().cloned());
        section(format!("[profiles.{name}]\n"), body);
    }
    let mut body = Vec::new();
    if let Some((name, _, _)) = &profile {
        body.push(format!("profile = {}\n", Value::String(name.clone())));
    }
    body.push(format!("folder = {}\n", Value::String(legacy.folder.clone())));
    let backend = match legacy.backend {
        BackendKind::Bitwarden => "bitwarden",
        BackendKind::Memory => "memory",
    };
    body.push(format!("backend = {}\n", Value::String(backend.into())));
    if legacy.backend == BackendKind::Memory {
        body.push(format!("memory_password = {}\n", Value::String(legacy.memory_password.clone())));
    }
    section("[bwss]\n".to_owned(), body);

    // Nothing is written unless the result is a file bwss accepts.
    let check: Table = toml::from_str(&text).context("the migrated config would not be valid TOML")?;
    config::resolve(&check).context("the migrated config would not be valid")?;
    let acl_off = legacy.acl == LegacyAcl::Off && confirm_acl_off()?;

    let mut old_files = vec![old.clone()];
    if let Some((name, _, _)) = &profile {
        if let Some(raw) = read_optional(&paths.legacy_credentials)?.map(Zeroizing::new) {
            let creds = paths.credentials(name);
            if std::fs::symlink_metadata(&creds).is_ok() {
                report.push(format!("kept the API key already in {}", creds.display()));
            } else {
                let found: LegacyCredentials = config::parse_secret_toml(&raw, &paths.legacy_credentials)?;
                // Bound to the server bwss will send it to: the profile's.
                let server =
                    own.and_then(|t| t.get("server_url")).and_then(Value::as_str).unwrap_or(&legacy.server_url);
                let origin = identity_origin(server).map_err(anyhow::Error::msg)?;
                let moved = Credentials {
                    identity_origin: origin.clone(),
                    client_id: found.client_id,
                    client_secret: found.client_secret,
                };
                config::save_credentials(&creds, &moved)?;
                report.push(format!("moved the API key to {}, bound to {origin}", creds.display()));
            }
            old_files.push(paths.legacy_credentials.clone());
        }
        let device = paths.state.join("device-id");
        if let Some(id) = read_optional(&device)? {
            let new = paths.device_id(name);
            if std::fs::symlink_metadata(&new).is_err() && !id.trim().is_empty() {
                crate::fsutil::write_private(&new, id.trim().as_bytes())?;
                report.push(format!("moved the device id to {}", new.display()));
            }
            old_files.push(device);
        }
    }

    crate::fsutil::write_atomic(&target, text.as_bytes(), mode_of(&target))
        .with_context(|| target.display().to_string())?;
    report.push(format!("wrote [bwss] to {}", paths.config.display()));
    if acl_off {
        config::set_acl_off(paths, true)?;
        report.push("access control is off on this device, as `acl = \"off\"` asked".to_owned());
    } else if legacy.acl == LegacyAcl::Off {
        report.push(
            "access control stays on: the old `acl = \"off\"` was not confirmed; \
             run `bwss acl off` on a terminal to turn it off"
                .to_owned(),
        );
    }
    let mut left = Vec::new();
    for file in old_files {
        match set_aside(&file) {
            Ok(aside) => report.push(format!("renamed {} to {}", file.display(), aside.display())),
            Err(e) => left.push(format!("{} ({e:#})", file.display())),
        }
    }
    if !left.is_empty() {
        bail!(
            "the migration is done, but these old files were not renamed; rename them yourself: {}\n{}",
            left.join(", "),
            report.join("\n")
        );
    }
    Ok(report)
}

#[cfg(all(test, unix))]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::config::{AclMode, BackendKind, acl_mode, load_credentials, load_settings, read_doc, resolve};
    use crate::fsutil::User;

    struct Home {
        dir: tempfile::TempDir,
        paths: Paths,
        trust: Trust,
        pinentry: PathBuf,
    }

    fn home() -> Home {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().canonicalize().unwrap().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let pinentry = bin.join("pinentry-qt");
        std::fs::write(&pinentry, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&pinentry, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let owner = std::fs::metadata(&bin).unwrap().uid();
        let trust = Trust {
            search: Some(bin.clone().into_os_string()),
            user: User { uid: owner.wrapping_add(1).max(1), groups: Some(vec![]) },
            exe: None,
            home: None,
        };
        let h = dir.path().as_os_str().to_owned();
        let paths = Paths::with(move |v| (v == "HOME").then(|| h.clone()));
        Home { dir, paths, trust, pinentry }
    }

    impl Home {
        fn legacy(&self, config: &str) {
            write(&self.paths.legacy_config, config);
        }

        fn legacy_credentials(&self) {
            write(&self.paths.legacy_credentials, "client_id = \"user.cid\"\nclient_secret = \"csecret\"\n");
            std::fs::set_permissions(&self.paths.legacy_credentials, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn dybw(&self, text: &str) {
            write(&self.paths.config, text);
        }

        fn run(&self, confirm: bool) -> anyhow::Result<Vec<String>> {
            let mut asked = || Ok(confirm);
            migrate(&self.paths, &self.trust, &mut asked)
        }

        fn text(&self) -> String {
            std::fs::read_to_string(&self.paths.config).unwrap()
        }

        fn me(&self) -> User {
            User { uid: std::fs::metadata(self.dir.path()).unwrap().uid(), groups: None }
        }
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn migrated(path: &Path) -> PathBuf {
        let mut p = path.as_os_str().to_owned();
        p.push(".migrated");
        PathBuf::from(p)
    }

    #[test]
    fn a_new_profile_carries_the_account_settings_credentials_and_device() {
        let h = home();
        h.legacy(&format!(
            "backend = \"bitwarden\"\nserver_url = \"https://vault.example.org\"\nemail = \"me@example.org\"\n\
             folder = \"keyring\"\nprompter = {:?}\nacl = \"off\"\nidle_lock_minutes = 10\n",
            h.pinentry
        ));
        h.legacy_credentials();
        write(&h.paths.state.join("device-id"), "dev-1234\n");

        let report = h.run(true).unwrap();
        assert!(report.iter().any(|l| l.contains("[profiles.bwss]")), "{report:?}");

        let s = load_settings(&h.paths).unwrap();
        let a = s.account.clone().unwrap();
        assert_eq!(
            (a.profile.as_str(), a.server_url.as_str(), a.email.as_str()),
            ("bwss", "https://vault.example.org", "me@example.org")
        );
        assert_eq!((s.backend, s.folder.as_str(), s.lock_timeout_minutes), (BackendKind::Bitwarden, "keyring", 10));
        assert_eq!(s.pinentry, h.pinentry.to_str().unwrap());
        assert_eq!(acl_mode(&h.paths), AclMode::Off);

        let creds = load_credentials(&h.paths.credentials("bwss"), &h.me(), "https://vault.example.org").unwrap();
        assert_eq!((creds.client_id.as_str(), creds.client_secret.as_str()), ("user.cid", "csecret"));
        assert_eq!(std::fs::read_to_string(h.paths.device_id("bwss")).unwrap().trim(), "dev-1234");

        for old in [&h.paths.legacy_config, &h.paths.legacy_credentials, &h.paths.state.join("device-id")] {
            assert!(!old.exists(), "{} is renamed", old.display());
            assert!(migrated(old).exists(), "{} is kept as *.migrated", old.display());
        }
        // Run again: the old file is gone, so there is nothing to do.
        assert!(format!("{:#}", h.run(true).unwrap_err()).contains("nothing to migrate"));
    }

    #[test]
    fn a_profile_with_the_same_account_is_reused_and_the_file_keeps_its_comments() {
        let h = home();
        let original = "# my dybw config\ndefault = \"personal\"\n\n[ssh_agent]\nprofiles = [\"personal\"]\n\n\
                        [profiles.personal] # mine\nserver_url = \"https://vault.example.org/\"\nemail = \"Me@Example.org\"\n";
        h.dybw(original);
        h.legacy("server_url = \"https://vault.example.org\"\nemail = \"me@example.org\"\n");
        h.legacy_credentials();
        h.run(false).unwrap();

        let text = h.text();
        assert!(text.starts_with(original), "{text}");
        assert!(!text.contains("[profiles.bwss]"), "{text}");
        let s = load_settings(&h.paths).unwrap();
        assert_eq!(s.account.unwrap().profile, "personal");
        assert_eq!(
            (s.lock_timeout_minutes, s.pinentry.as_str(), s.folder.as_str()),
            (60, "pinentry", "secret-service")
        );
        assert!(h.paths.credentials("personal").exists());
    }

    #[test]
    fn overrides_go_under_the_reused_profile_unless_it_sets_them() {
        let h = home();
        h.dybw(
            "default = \"personal\"\n[profiles.personal]\nserver_url = \"https://vault.example.org\"\nemail = \"me@example.org\"\n\
             [profiles.work]\nserver_url = \"https://w.example\"\nemail = \"w@example\"\n",
        );
        h.legacy(&format!(
            "server_url = \"https://vault.example.org\"\nemail = \"me@example.org\"\nidle_lock_minutes = 15\nprompter = {:?}\n",
            h.pinentry
        ));
        h.run(false).unwrap();
        let doc = read_doc(&h.paths.config).unwrap().unwrap();
        let s = resolve(&doc).unwrap();
        assert_eq!((s.lock_timeout_minutes, s.pinentry.as_str()), (15, h.pinentry.to_str().unwrap()));
        assert!(doc["profiles"]["work"].get("lock_timeout_minutes").is_none(), "only the served profile changes");

        let h = home();
        h.dybw(
            "lock_timeout_minutes = 15\n[profiles.p]\nserver_url = \"https://vault.example.org\"\nemail = \"me@example.org\"\n\
             lock_timeout_minutes = 5\n",
        );
        h.legacy("server_url = \"https://vault.example.org\"\nemail = \"me@example.org\"\nidle_lock_minutes = 15\n");
        let report = h.run(false).unwrap();
        assert_eq!(load_settings(&h.paths).unwrap().lock_timeout_minutes, 5, "the profile's own value is kept");
        assert!(report.iter().any(|l| l.contains("lock_timeout_minutes") && l.contains("kept")), "{report:?}");
    }

    #[test]
    fn a_zero_idle_lock_is_not_carried_over() {
        let h = home();
        h.legacy("email = \"me@example.org\"\nidle_lock_minutes = 0\n");
        h.run(false).unwrap();
        assert!(!h.text().contains("lock_timeout_minutes"), "{}", h.text());
        assert_eq!(load_settings(&h.paths).unwrap().lock_timeout_minutes, 60);
    }

    #[test]
    fn acl_off_needs_the_users_confirmation() {
        let h = home();
        h.legacy("email = \"me@example.org\"\nacl = \"off\"\n");
        let report = h.run(false).unwrap();
        assert_eq!(acl_mode(&h.paths), AclMode::Prompt);
        assert!(report.iter().any(|l| l.contains("bwss acl off")), "{report:?}");
        assert!(!h.text().contains("acl"), "{}", h.text());
    }

    #[test]
    fn an_untrusted_prompter_stops_the_migration_before_any_change() {
        let h = home();
        let legacy = "email = \"me@example.org\"\nprompter = \"/tmp/evil-pinentry\"\n";
        h.legacy(legacy);
        h.legacy_credentials();
        let e = format!("{:#}", h.run(true).unwrap_err());
        assert!(e.contains("prompter"), "{e}");
        assert!(!h.paths.config.exists());
        assert_eq!(std::fs::read_to_string(&h.paths.legacy_config).unwrap(), legacy);
        assert!(h.paths.legacy_credentials.exists());
        assert!(!h.paths.credentials("bwss").exists());
    }

    #[test]
    fn what_cannot_be_migrated_is_refused() {
        let h = home();
        assert!(format!("{:#}", h.run(true).unwrap_err()).contains("nothing to migrate"));
        std::fs::create_dir_all(&h.paths.legacy_config).unwrap();
        let e = format!("{:#}", h.run(true).unwrap_err());
        assert!(e.contains("config.toml") && !e.contains("nothing to migrate"), "{e}");
        std::fs::remove_dir(&h.paths.legacy_config).unwrap();

        h.legacy("email = \"me@example.org\"\nwhole_vault = true\n");
        assert!(format!("{:#}", h.run(true).unwrap_err()).contains("whole_vault"));

        h.legacy("backend = \"bitwarden\"\n");
        assert!(format!("{:#}", h.run(true).unwrap_err()).contains("email"));

        h.legacy("email = \"me@example.org\"\n");
        h.dybw("[bwss]\n");
        assert!(format!("{:#}", h.run(true).unwrap_err()).contains("[bwss]"));

        h.dybw("[profiles.bwss]\nserver_url = \"https://other.example\"\nemail = \"x@y\"\n");
        let e = format!("{:#}", h.run(true).unwrap_err());
        assert!(e.contains("[profiles.bwss]"), "{e}");

        // The result must still be a valid file.
        h.dybw("profiles = { personal = { server_url = \"https://a\", email = \"b\" } }\n");
        assert!(h.run(true).is_err());
        assert!(h.paths.legacy_config.exists());
    }

    #[test]
    fn a_profile_without_a_header_line_cannot_take_an_override() {
        let h = home();
        let original = "profiles.p.server_url = \"https://vault.example.org\"\nprofiles.p.email = \"me@example.org\"\n\
                        [ssh_agent]\nprofiles = [\"p\"]\n";
        h.dybw(original);
        h.legacy("server_url = \"https://vault.example.org\"\nemail = \"me@example.org\"\nidle_lock_minutes = 15\n");
        let e = format!("{:#}", h.run(false).unwrap_err());
        assert!(e.contains("[profiles.p]") && e.contains("lock_timeout_minutes = 15"), "{e}");
        assert_eq!(h.text(), original);

        // Without an override to place, the profile is simply used.
        h.legacy("server_url = \"https://vault.example.org\"\nemail = \"me@example.org\"\n");
        h.run(false).unwrap();
        assert_eq!(load_settings(&h.paths).unwrap().account.unwrap().profile, "p");
    }

    #[test]
    fn a_result_bwss_would_refuse_is_never_written() {
        let h = home();
        h.dybw("auth = \"password\"\n");
        h.legacy("email = \"me@example.org\"\n");
        let e = format!("{:#}", h.run(false).unwrap_err());
        assert!(e.contains("not be valid") && e.contains("api-key"), "{e}");
        assert_eq!(h.text(), "auth = \"password\"\n");
    }

    #[test]
    fn the_top_level_takes_the_overrides_without_a_profile() {
        let h = home();
        h.dybw("sync_interval_seconds = 60"); // no final line break
        h.legacy(&format!(
            "backend = \"memory\"\nidle_lock_minutes = 5\nprompter = {:?}\nsync_interval_seconds = 90\n",
            h.pinentry
        ));
        let report = h.run(false).unwrap();
        let s = load_settings(&h.paths).unwrap();
        assert_eq!((s.lock_timeout_minutes, s.pinentry.as_str()), (5, h.pinentry.to_str().unwrap()));
        assert_eq!(s.sync_interval_seconds, 60);
        assert!(
            report.iter().any(|l| l.contains("sync_interval_seconds = 90") && l.contains("not carried")),
            "{report:?}"
        );
    }

    #[test]
    fn old_files_never_overwrite_an_earlier_migrated_copy() {
        let h = home();
        h.legacy("email = \"me@example.org\"\n");
        write(&migrated(&h.paths.legacy_config), "earlier\n");
        h.run(false).unwrap();
        assert_eq!(std::fs::read_to_string(migrated(&h.paths.legacy_config)).unwrap(), "earlier\n");
        let second = PathBuf::from(format!("{}.migrated.2", h.paths.legacy_config.display()));
        assert_eq!(std::fs::read_to_string(second).unwrap(), "email = \"me@example.org\"\n");
    }

    #[test]
    fn broken_old_credentials_never_show_their_secret() {
        let h = home();
        h.legacy("email = \"me@example.org\"\n");
        write(&h.paths.legacy_credentials, "client_id = \"cid\"\nclient_secret = \"s3cr3t-leak\n");
        let e = format!("{:#}", h.run(false).unwrap_err());
        assert!(!e.contains("s3cr3t") && e.contains("credentials.toml"), "{e}");
        assert!(!h.paths.config.exists(), "nothing written");
    }

    #[test]
    fn the_key_is_bound_to_the_reused_profiles_server() {
        let h = home();
        // Same server, spelt differently: the profile's spelling decides.
        h.dybw("[profiles.p]\nserver_url = \"https://VAULT.example.org/\"\nemail = \"me@example.org\"\n");
        h.legacy("server_url = \"https://vault.example.org\"\nemail = \"me@example.org\"\n");
        h.legacy_credentials();
        h.run(false).unwrap();
        let text = std::fs::read_to_string(h.paths.credentials("p")).unwrap();
        assert!(text.contains("identity_origin = \"https://vault.example.org\""), "{text}");
    }

    #[test]
    fn the_dybw_file_keeps_its_mode() {
        let h = home();
        h.dybw("# mine\n");
        std::fs::set_permissions(&h.paths.config, std::fs::Permissions::from_mode(0o644)).unwrap();
        h.legacy("email = \"me@example.org\"\n");
        h.run(false).unwrap();
        assert_eq!(std::fs::metadata(&h.paths.config).unwrap().mode() & 0o777, 0o644);
    }

    #[test]
    fn a_dangling_link_is_not_replaced() {
        let h = home();
        std::fs::create_dir_all(h.paths.config.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(h.dir.path().join("gone/config.toml"), &h.paths.config).unwrap();
        h.legacy("email = \"me@example.org\"\n");
        let e = format!("{:#}", h.run(false).unwrap_err());
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound).to_string();
        assert!(e.contains("link") && e.contains("gone/config.toml"), "{e}");
        assert!(e.contains(&missing) || e.contains("No such file"), "the real reason: {e}");
        assert!(std::fs::symlink_metadata(&h.paths.config).unwrap().file_type().is_symlink());
        assert!(h.paths.legacy_config.exists());

        // A loop says so, rather than "does not exist".
        std::fs::remove_file(&h.paths.config).unwrap();
        std::os::unix::fs::symlink(&h.paths.config, &h.paths.config).unwrap();
        let e = format!("{:#}", h.run(false).unwrap_err());
        assert!(!e.contains("does not exist") && e.to_lowercase().contains("symbolic links"), "{e}");
    }

    #[test]
    fn files_left_behind_by_a_failed_rename_are_named() {
        let h = home();
        h.legacy("email = \"me@example.org\"\n");
        h.legacy_credentials();
        let dir = h.paths.legacy_config.parent().unwrap().to_owned();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let probe = std::fs::File::create(dir.join("probe"));
        if probe.is_ok() {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            return; // permissions not enforced (running as root)
        }
        let e = format!("{:#}", h.run(false).unwrap_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(e.contains("not renamed") && e.contains("config.toml") && e.contains("credentials.toml"), "{e}");
        assert!(e.contains("wrote [bwss]"), "what was done is reported too: {e}");
    }

    #[test]
    fn the_memory_backend_needs_no_profile() {
        let h = home();
        h.legacy("backend = \"memory\"\nmemory_password = \"open sesame\"\n");
        h.run(false).unwrap();
        let s = load_settings(&h.paths).unwrap();
        assert_eq!((s.backend, s.account, s.memory_password.as_str()), (BackendKind::Memory, None, "open sesame"));
    }

    #[test]
    fn existing_credentials_of_the_profile_are_kept() {
        let h = home();
        h.legacy("email = \"me@example.org\"\n");
        h.legacy_credentials();
        write(&h.paths.state.join("device-id"), "old-device\n");
        write(&h.paths.device_id("bwss"), "dybw-device");
        write(&h.paths.credentials("bwss"), "identity_origin = \"https://identity.bitwarden.com\"\n");
        let report = h.run(false).unwrap();
        assert!(report.iter().any(|l| l.contains("kept")), "{report:?}");
        assert_eq!(
            std::fs::read_to_string(h.paths.credentials("bwss")).unwrap(),
            "identity_origin = \"https://identity.bitwarden.com\"\n"
        );
        assert!(migrated(&h.paths.legacy_credentials).exists());
        assert_eq!(std::fs::read_to_string(h.paths.device_id("bwss")).unwrap(), "dybw-device");
        assert!(migrated(&h.paths.state.join("device-id")).exists());
    }

    #[test]
    fn a_linked_dybw_file_is_written_through_the_link() {
        let h = home();
        let real = h.dir.path().join("dotfiles/config.toml");
        write(&real, "# managed\n");
        std::fs::create_dir_all(h.paths.config.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&real, &h.paths.config).unwrap();
        h.legacy("email = \"me@example.org\"\n");
        h.run(false).unwrap();
        assert!(std::fs::symlink_metadata(&h.paths.config).unwrap().file_type().is_symlink());
        assert!(std::fs::read_to_string(&real).unwrap().contains("[bwss]"));
    }
}
