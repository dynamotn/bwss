//! bwss — a freedesktop Secret Service backed by a Bitwarden vault.

mod acl;
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

use std::io::{BufRead, IsTerminal};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use zbus::fdo::{RequestNameFlags, RequestNameReply};
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
    /// Unlock the keyring (master password from stdin, or the configured prompter).
    Unlock {
        /// Read the password from the first line of stdin.
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

async fn control() -> anyhow::Result<zbus::Proxy<'static>> {
    let conn = zbus::Connection::session().await.context("cannot reach the session bus")?;
    Ok(zbus::Proxy::new(&conn, CONTROL_NAME, CONTROL_PATH, CONTROL_IFACE).await?)
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

    let conn = zbus::connection::Builder::session().build().await?;
    daemon.set_connection(conn.clone());
    dbus::serve(&daemon).await?;
    let mut flags = RequestNameFlags::DO_NOT_QUEUE | RequestNameFlags::ALLOW_REPLACEMENT;
    if replace {
        flags |= RequestNameFlags::REPLACE_EXISTING;
    }
    match conn.request_name_with_flags(SECRETS_NAME, flags).await? {
        RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner => {}
        _ => bail!("{SECRETS_NAME} is owned by another provider (gnome-keyring, KWallet, KeePassXC?); use --replace"),
    }
    conn.request_name_with_flags(CONTROL_NAME, RequestNameFlags::DO_NOT_QUEUE).await?;
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
        Command::Unlock { password_stdin } => {
            let proxy = control().await?;
            let password = if password_stdin || !std::io::stdin().is_terminal() {
                read_line_secret("", true)?
            } else {
                let config = load_config(&Paths::from_env())?;
                Prompter::new(config.prompter, Duration::from_secs(120))
                    .password("Unlock the bwss keyring.", None)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("cancelled"))?
            };
            proxy.call::<_, _, ()>("UnlockWithPassword", &(password.as_str(),)).await.context("unlock failed")?;
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
