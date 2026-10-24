//! bwss — a freedesktop Secret Service backed by a Bitwarden vault.

mod acl;
mod acl_confirm;
mod backend;
mod bw;
mod config;
mod daemon;
mod dbus;
mod fsutil;
mod keyring;
mod model;
#[cfg(test)]
mod perf;
mod prompter;
mod session;
mod sync;

use std::io::{BufRead, IsTerminal};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use zbus::fdo::{DBusProxy, RequestNameFlags, RequestNameReply};
use zbus::names::BusName;
use zeroize::Zeroizing;

use crate::backend::{Backend, bitwarden::BitwardenBackend, memory::MemoryBackend};
use crate::config::{BackendKind, Credentials, Paths, load_config};
use crate::daemon::Daemon;
use crate::dbus::{CONTROL_NAME, CONTROL_PATH};
use crate::keyring::Keyring;
use crate::prompter::Prompter;

const SECRETS_NAME: &str = "org.freedesktop.secrets";
const CONTROL_IFACE: &str = "io.github.dynamotn.bwss.Control1";

#[derive(Parser)]
#[command(version, about = "Secret Service (org.freedesktop.secrets) backed by Bitwarden")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the Secret Service on the session bus.
    Daemon {
        /// Take over org.freedesktop.secrets from another running provider.
        #[arg(long)]
        replace: bool,
    },
    /// Unlock the keyring: the daemon asks through its prompter, or the
    /// master password comes from stdin.
    Unlock {
        /// Read the password from the first line of stdin and send it to the
        /// daemon, after checking that the daemon is this same bwss binary.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Lock the keyring and forget the keys.
    Lock,
    /// Pull changes from Bitwarden now.
    Sync,
    /// Show whether the keyring is unlocked.
    Status,
    /// Save the Bitwarden account and API key.
    Login {
        #[arg(long)]
        email: String,
        #[arg(long, default_value = "https://vault.bitwarden.com")]
        server: String,
        #[arg(long)]
        client_id: String,
        /// Read the client secret from the first line of stdin instead of asking.
        #[arg(long)]
        client_secret_stdin: bool,
    },
}

fn read_line_secret(prompt: &str, from_stdin: bool) -> anyhow::Result<Zeroizing<String>> {
    if !from_stdin && std::io::stdin().is_terminal() {
        eprint!("{prompt}");
    }
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    let trimmed = Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned());
    if trimmed.is_empty() {
        bail!("no input");
    }
    Ok(trimmed)
}

async fn session_bus() -> anyhow::Result<zbus::Connection> {
    zbus::Connection::session().await.context("cannot reach the session bus")
}

async fn control() -> anyhow::Result<zbus::Proxy<'static>> {
    Ok(zbus::Proxy::new(&session_bus().await?, CONTROL_NAME, CONTROL_PATH, CONTROL_IFACE).await?)
}

/// The control interface of the connection that owns `CONTROL_NAME`, after
/// checking that it runs this same binary. The proxy talks to that unique
/// name, so the owner cannot change between the check and the call.
async fn verified_control() -> anyhow::Result<zbus::Proxy<'static>> {
    require_proc()?;
    let conn = session_bus().await?;
    let bus = DBusProxy::new(&conn).await?;
    let owner = bus
        .get_name_owner(BusName::try_from(CONTROL_NAME)?)
        .await
        .with_context(|| format!("{CONTROL_NAME} is not on the bus; is the bwss daemon running?"))?;
    let pid = bus.get_connection_unix_process_id(BusName::Unique(owner.as_ref())).await?;
    let me = std::env::current_exe().context("cannot find this executable")?;
    // A speed bump against processes of the same user, like the item ACL:
    // it holds as long as the CLI and the daemon are the same installed file.
    match acl::executable_of(pid) {
        Some(exe) if acl::same_executable(&exe, &me) => {}
        found => bail!(
            "refusing to send the password: {CONTROL_NAME} is owned by {} (pid {pid}), not {}",
            found.as_deref().unwrap_or(acl::UNKNOWN),
            me.display()
        ),
    }
    if !acl::runs_daemon(pid) {
        bail!("refusing to send the password: {CONTROL_NAME} is owned by pid {pid}, which is not a `bwss daemon`");
    }
    Ok(zbus::Proxy::new(&conn, owner.into_inner(), CONTROL_PATH, CONTROL_IFACE).await?)
}

/// The owner check reads `/proc/<pid>/exe`, which only Linux has.
#[cfg(target_os = "linux")]
fn require_proc() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn require_proc() -> anyhow::Result<()> {
    bail!("--password-stdin needs Linux (/proc) to check who owns {CONTROL_NAME}; run `bwss unlock` without it")
}

/// "<executable> (pid N)" of whoever owns `name`, for error messages.
async fn owner_of(bus: &DBusProxy<'_>, name: &str) -> String {
    let Ok(name) = BusName::try_from(name) else { return acl::UNKNOWN.into() };
    let Ok(owner) = bus.get_name_owner(name).await else { return acl::UNKNOWN.into() };
    let pid = bus.get_connection_unix_process_id(BusName::Unique(owner.as_ref())).await.ok();
    let exe = pid.and_then(acl::executable_of);
    let who = pid.map_or_else(|| owner.to_string(), |pid| format!("pid {pid}"));
    format!("{} ({who})", exe.as_deref().unwrap_or(acl::UNKNOWN))
}

fn name_refusal(name: &str, owner: &str, replace: bool) -> String {
    if name == SECRETS_NAME {
        if replace {
            format!("{name} is owned by {owner}, which does not allow replacement")
        } else {
            format!("{name} is owned by {owner} (gnome-keyring, KWallet, KeePassXC?); use --replace")
        }
    } else {
        format!("{name} is owned by {owner}: another bwss, or a process squatting the name; stop it first")
    }
}

/// Takes `name` as its only owner, or says who holds it.
async fn claim(conn: &zbus::Connection, name: &'static str, replace: bool) -> anyhow::Result<()> {
    // No ALLOW_REPLACEMENT: nobody can take a name from bwss with REPLACE_EXISTING.
    let mut flags = RequestNameFlags::DO_NOT_QUEUE;
    if replace {
        flags |= RequestNameFlags::REPLACE_EXISTING;
    }
    let reply = match conn.request_name_with_flags(name, flags).await {
        // zbus turns the `Exists` reply into this error.
        Err(zbus::Error::NameTaken) => RequestNameReply::Exists,
        other => other?,
    };
    if matches!(reply, RequestNameReply::PrimaryOwner) {
        return Ok(());
    }
    let owner = owner_of(&DBusProxy::new(conn).await?, name).await;
    bail!("{}", name_refusal(name, &owner, replace))
}

/// Takes both bus names or neither. The control name goes first and is never
/// replaced: whoever holds it receives `bwss unlock --password-stdin`.
async fn claim_names(conn: &zbus::Connection, replace: bool) -> anyhow::Result<()> {
    claim(conn, CONTROL_NAME, false).await?;
    if let Err(e) = claim(conn, SECRETS_NAME, replace).await {
        let _ = conn.release_name(CONTROL_NAME).await;
        return Err(e);
    }
    Ok(())
}

async fn run_daemon(replace: bool) -> anyhow::Result<()> {
    let paths = Paths::from_env();
    let config = load_config(&paths)?;
    let (backend, index): (Arc<dyn Backend>, _) = match config.backend {
        BackendKind::Memory => (Arc::new(MemoryBackend::new(config.memory_password.clone())), None),
        BackendKind::Bitwarden => {
            if config.email.is_empty() {
                bail!("set `email` in {} (or run `bwss login`)", paths.config.display());
            }
            let creds = config::load_credentials(&paths)?;
            let b = BitwardenBackend::new(&config, creds, &paths)?;
            (Arc::new(b), Some(paths.cache.join("locked-index.json")))
        }
    };
    let prompter = Prompter::new(config.prompter.clone(), Duration::from_secs(120));
    let daemon = Daemon::new(Keyring::new(index), backend, prompter, config.clone());
    daemon.set_acl_state_path(paths.tool_state.join("acl-confirmed"));

    let conn = zbus::connection::Builder::session().build().await?;
    daemon.set_connection(conn.clone());
    dbus::serve(&daemon).await?;
    claim_names(&conn, replace).await?;
    tracing::info!("serving {SECRETS_NAME}");

    // Periodic pull from Bitwarden.
    let d = daemon.clone();
    let interval = Duration::from_secs(config.sync_interval_seconds.max(30));
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            d.refresh().await;
        }
    });
    // Idle lock.
    if config.idle_lock_minutes > 0 {
        let d = daemon.clone();
        let limit = Duration::from_secs(config.idle_lock_minutes * 60);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                if d.keyring.lock().await.is_unlocked() && d.idle_for() > limit {
                    d.lock().await;
                }
            }
        });
    }

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    daemon.lock().await;
    Ok(())
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Daemon { replace } => run_daemon(replace).await,
        Command::Unlock { password_stdin: true } => {
            let proxy = verified_control().await?;
            let password = read_line_secret("", true)?;
            proxy.call::<_, _, ()>("UnlockWithPassword", &(password.as_str(),)).await.context("unlock failed")?;
            println!("unlocked");
            Ok(())
        }
        Command::Unlock { password_stdin: false } => {
            let unlocked: bool = control().await?.call("UnlockInteractive", &()).await?;
            if !unlocked {
                bail!("unlock cancelled or failed");
            }
            println!("unlocked");
            Ok(())
        }
        Command::Lock => {
            control().await?.call::<_, _, ()>("Lock", &()).await?;
            println!("locked");
            Ok(())
        }
        Command::Sync => {
            control().await?.call::<_, _, ()>("Sync", &()).await?;
            Ok(())
        }
        Command::Status => {
            let (unlocked, items, backend): (bool, u32, String) = control().await?.call("Status", &()).await?;
            // The first line is the summary; the backend may add lines with
            // what the user may want to fix (duplicates, skipped items).
            let (summary, details) = backend.split_once('\n').unwrap_or((backend.as_str(), ""));
            println!("{}, {items} item(s), {summary}", if unlocked { "unlocked" } else { "locked" });
            for line in details.lines() {
                println!("  {line}");
            }
            Ok(())
        }
        Command::Login { email, server, client_id, client_secret_stdin } => {
            crate::bw::api::resolve_server_urls(&server).map_err(anyhow::Error::msg)?;
            let secret = read_line_secret("API key client_secret: ", client_secret_stdin)?;
            let paths = Paths::from_env();
            let mut config = load_config(&paths)?;
            config.email = email;
            config.server_url = server;
            config.backend = BackendKind::Bitwarden;
            fsutil::write_private(&paths.config, toml::to_string_pretty(&config)?.as_bytes())?;
            let creds = Credentials { client_id, client_secret: secret };
            fsutil::write_private(&paths.credentials, Zeroizing::new(toml::to_string(&creds)?).as_bytes())?;
            println!("saved {} and {}", paths.config.display(), paths.credentials.display());
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("BWSS_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    match run(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bwss: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_taken_name_says_who_holds_it_and_what_to_do() {
        let owner = "/usr/bin/python3 (pid 42)";
        let control = name_refusal(CONTROL_NAME, owner, true);
        assert!(control.contains(CONTROL_NAME) && control.contains(owner), "{control}");
        assert!(!control.contains("--replace"), "--replace never takes the control name: {control}");

        let secrets = name_refusal(SECRETS_NAME, owner, false);
        assert!(secrets.contains(owner) && secrets.contains("use --replace"), "{secrets}");
        let replaced = name_refusal(SECRETS_NAME, owner, true);
        assert!(replaced.contains(owner) && replaced.contains("does not allow replacement"), "{replaced}");
    }
}
