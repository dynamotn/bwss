//! bwss — a freedesktop Secret Service backed by a Bitwarden vault.

mod acl;
mod acl_confirm;
mod backend;
mod bw;
mod config;
mod daemon;
mod dbus;
mod fsutil;
mod hardening;
mod keyring;
mod logind;
mod migrate;
mod model;
#[cfg(test)]
mod perf;
mod prompter;
mod session;
mod sync;

use std::io::{BufRead, IsTerminal, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand, ValueEnum};
use zbus::fdo::{DBusProxy, RequestNameFlags, RequestNameReply};
use zbus::names::BusName;
use zeroize::Zeroizing;

use crate::backend::{Backend, bitwarden::BitwardenBackend, memory::MemoryBackend};
use crate::bw::api::identity_origin;
use crate::config::{BackendKind, Credentials, Paths, Trust};
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
        /// daemon over the session bus. The check that the daemon is this
        /// same bwss binary is best effort; plain `bwss unlock` asks through
        /// the daemon's own pinentry and sends no password.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Lock the keyring and forget the keys.
    Lock,
    /// Pull changes from Bitwarden now.
    Sync,
    /// Show whether the keyring is unlocked.
    Status,
    /// Save the API key of the profile bwss serves, bound to its server.
    Login {
        #[arg(long)]
        client_id: String,
        /// Read the client secret from the first line of stdin instead of asking.
        #[arg(long)]
        client_secret_stdin: bool,
    },
    /// Turn per-application access control off or on, on this device.
    Acl {
        #[arg(value_enum)]
        mode: Switch,
    },
    /// Choose what the locked index holds on this device.
    Index {
        #[command(subcommand)]
        command: IndexCommand,
    },
    /// Manage the configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Switch {
    Off,
    On,
}

#[derive(Subcommand)]
enum IndexCommand {
    /// Put the derived attributes (bwss:id, bwss:name, bwss:username,
    /// bwss:uri) in the locked index, or take them out (the default).
    Derived {
        #[arg(value_enum)]
        mode: Switch,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Move ~/.config/bwss/config.toml into the shared dybw file.
    Migrate,
}

const ACL_OFF_QUESTION: &str = "Turn off per-application access control on this device?\n\
    Every program running as you could then use every keyring item without being asked.\n\
    Type \"yes\" to turn it off: ";

/// The question before derived attributes go in the locked index at `index`.
fn index_derived_question(index: &std::path::Path) -> String {
    format!(
        "Put derived attributes (bwss:id, bwss:name, bwss:username, bwss:uri) in the locked index on this device?\n\
         Item names, usernames and URIs then become guessable offline from ~/.cache: anyone who can read\n\
         {} can test guesses of them without the master password.\n\
         Type \"yes\" to turn it on: ",
        index.display()
    )
}

/// Asks `question` on the terminal; only "yes" confirms.
fn confirm(question: &str, tty: bool, input: &mut dyn BufRead, out: &mut dyn Write) -> anyhow::Result<bool> {
    if !tty {
        bail!("this needs a confirmation on a terminal, and stdin is not one");
    }
    write!(out, "{question}")?;
    out.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    Ok(line.trim().eq_ignore_ascii_case("yes"))
}

fn confirm_on_terminal(question: &str) -> anyhow::Result<bool> {
    confirm(question, std::io::stdin().is_terminal(), &mut std::io::stdin().lock(), &mut std::io::stderr())
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
    // A best-effort speed bump against processes of the same user. The
    // daemon is not dumpable, so its /proc/<pid>/exe is unreadable: the check
    // uses its user, command line and start time instead (TM-013).
    let my_uid = fsutil::User::current().context("cannot tell which user this is")?.uid;
    if let Err(why) = acl::check_daemon_owner(pid, &me, my_uid) {
        let who = acl::executable_of(pid).unwrap_or_else(|| acl::UNKNOWN.to_owned());
        bail!("refusing to send the password: {CONTROL_NAME} is owned by {who} (pid {pid}), {why}");
    }
    Ok(zbus::Proxy::new(&conn, owner.into_inner(), CONTROL_PATH, CONTROL_IFACE).await?)
}

/// The owner check reads `/proc/<pid>/{status,cmdline,stat}`, which only Linux has.
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
    let who = pid.map_or(owner.to_string(), |pid| format!("pid {pid}"));
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

/// The pinentry check that runs right before every start: `Err` says why not.
fn verify_pinentry(trust: &Trust, program: &str) -> Result<(), String> {
    trust.verify(std::path::Path::new(program)).map(|_| ()).map_err(|e| format!("{e:#}"))
}

/// Warns about each step of the process hardening that did not work.
fn log_hardening_failures(failures: impl IntoIterator<Item = String>) {
    for failure in failures {
        tracing::warn!("process hardening incomplete: {failure}");
    }
}

/// Pulls from the backend every `period`, the first time one period from now.
fn spawn_sync(d: Arc<Daemon>, period: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        tick.tick().await;
        loop {
            tick.tick().await;
            d.refresh().await;
        }
    })
}

/// Locks the keyring once it has been idle for more than `limit`, checking
/// every `poll`.
fn spawn_idle_lock(d: Arc<Daemon>, limit: Duration, poll: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(poll);
        loop {
            tick.tick().await;
            if d.keyring.lock().await.is_unlocked() && d.idle_for() > limit {
                d.lock().await;
            }
        }
    })
}

async fn run_daemon(replace: bool) -> anyhow::Result<()> {
    log_hardening_failures(hardening::harden());
    let paths = Paths::from_env();
    let trust = Trust::system()?;
    let config = config::load(&paths, &trust)?;
    for dir in [&paths.cache, &paths.state, &paths.tool_state] {
        fsutil::ensure_private_dir(dir).with_context(|| format!("{}", dir.display()))?;
    }
    let (backend, index): (Arc<dyn Backend>, _) = match config.backend {
        BackendKind::Memory => (Arc::new(MemoryBackend::new(config.memory_password.clone())), None),
        BackendKind::Bitwarden => {
            let profile = config.profile.as_deref().context("bwss serves no profile")?;
            for dir in [paths.profile_dir(profile), paths.devices(profile)] {
                fsutil::ensure_private_dir(&dir).with_context(|| format!("{}", dir.display()))?;
            }
            let origin = identity_origin(&config.server_url).map_err(anyhow::Error::msg)?;
            let creds = config::load_credentials(&paths.credentials(profile), &trust.user, &origin)?;
            let b = BitwardenBackend::new(&config, creds, &paths)?;
            (Arc::new(b), Some(paths.locked_index()))
        }
    };
    // The pinentry is checked again right before every start (ADR 0008).
    let guard = Arc::new(trust);
    let prompter = Prompter::guarded(
        config.pinentry.clone(),
        Duration::from_secs(120),
        Arc::new(move |program: &str| verify_pinentry(&guard, program)),
    );
    let daemon = Daemon::new(Keyring::new(index, Some(paths.index_derived())), backend, prompter, config.clone());
    daemon.set_acl_state_path(paths.tool_state.join("acl-confirmed"));

    let conn = zbus::connection::Builder::session().build().await?;
    daemon.set_connection(conn.clone());
    dbus::serve(&daemon).await?;
    claim_names(&conn, replace).await?;
    tracing::info!("serving {SECRETS_NAME}");

    // Periodic pull from Bitwarden.
    spawn_sync(daemon.clone(), Duration::from_secs(config.sync_interval_seconds.max(30)));
    // Idle lock.
    if config.lock_timeout_minutes > 0 {
        let limit = Duration::from_secs(config.lock_timeout_minutes.saturating_mul(60));
        spawn_idle_lock(daemon.clone(), limit, Duration::from_secs(30));
    }

    // Sleep and screen lock, from logind on the system bus.
    let d = daemon.clone();
    tokio::spawn(logind::run(move || {
        let d = d.clone();
        async move { d.lock().await }
    }));

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    daemon.lock().await;
    Ok(())
}

/// What `bwss status` prints. The first line of `backend` is the summary; the
/// backend may add lines with what the user may want to fix (duplicates,
/// skipped items), which are indented.
fn status_lines(unlocked: bool, items: u32, backend: &str) -> Vec<String> {
    let (summary, details) = backend.split_once('\n').unwrap_or((backend, ""));
    let mut lines = vec![format!("{}, {items} item(s), {summary}", if unlocked { "unlocked" } else { "locked" })];
    lines.extend(details.lines().map(|line| format!("  {line}")));
    lines
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    config::refuse_root(&fsutil::User::current().context("cannot tell which user this is")?)?;
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
            for line in status_lines(unlocked, items, &backend) {
                println!("{line}");
            }
            Ok(())
        }
        Command::Login { client_id, client_secret_stdin } => {
            let paths = Paths::from_env();
            let account = config::load_settings(&paths)?.account.with_context(|| {
                format!("bwss serves no profile: set `default` or `[bwss] profile` in {}", paths.config.display())
            })?;
            let origin = identity_origin(&account.server_url).map_err(anyhow::Error::msg)?;
            let client_secret = read_line_secret("API key client_secret: ", client_secret_stdin)?;
            let path = paths.credentials(&account.profile);
            config::save_credentials(
                &path,
                &Credentials { identity_origin: origin.clone(), client_id, client_secret },
            )?;
            println!(
                "saved the API key of profile {} ({}, {origin}) in {}",
                account.profile,
                account.email,
                path.display()
            );
            Ok(())
        }
        Command::Acl { mode } => {
            let paths = Paths::from_env();
            let off = matches!(mode, Switch::Off);
            if off && !confirm_on_terminal(ACL_OFF_QUESTION)? {
                bail!("not confirmed; access control stays on");
            }
            config::set_acl_off(&paths, off).with_context(|| format!("{}", paths.acl_off().display()))?;
            println!(
                "access control is {} on this device; restart the bwss daemon to apply it",
                if off { "off" } else { "on" }
            );
            Ok(())
        }
        Command::Index { command: IndexCommand::Derived { mode } } => {
            let paths = Paths::from_env();
            let on = matches!(mode, Switch::On);
            if on && !confirm_on_terminal(&index_derived_question(&paths.locked_index()))? {
                bail!("not confirmed; derived attributes stay out of the locked index");
            }
            config::set_index_derived(&paths, on).with_context(|| format!("{}", paths.index_derived().display()))?;
            println!(
                "derived attributes are {} the locked index on this device from its next write \
                 (the next unlock or change)",
                if on { "in" } else { "out of" }
            );
            Ok(())
        }
        Command::Config { command: ConfigCommand::Migrate } => {
            let paths = Paths::from_env();
            let mut ask = || {
                if std::io::stdin().is_terminal() { confirm_on_terminal(ACL_OFF_QUESTION) } else { Ok(false) }
            };
            for line in migrate::migrate(&paths, &Trust::system()?, &mut ask)? {
                println!("{line}");
            }
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
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn only_yes_on_a_terminal_confirms() {
        let ask = |tty: bool, answer: &str| {
            let mut out = Vec::new();
            let r = confirm("Sure? ", tty, &mut answer.as_bytes(), &mut out);
            (r.map_err(|e| e.to_string()), String::from_utf8_lossy(&out).into_owned())
        };
        assert_eq!(ask(true, "yes\n"), (Ok(true), "Sure? ".to_owned()));
        assert_eq!(ask(true, " YES \n").0, Ok(true));
        assert_eq!(ask(true, "y\n").0, Ok(false));
        assert_eq!(ask(true, "").0, Ok(false));
        let (refused, said) = ask(false, "yes\n");
        assert!(refused.is_err_and(|e| e.contains("terminal")));
        assert!(said.is_empty(), "nothing is asked without a terminal");
    }

    #[test]
    fn turning_derived_attributes_on_says_what_becomes_guessable() {
        let q = index_derived_question(std::path::Path::new("/home/u/.cache/bwss/locked-index.json"));
        assert!(q.contains("usernames and URIs") && q.contains("guessable offline"), "{q}");
        assert!(q.contains("~/.cache") && q.contains("/home/u/.cache/bwss/locked-index.json"), "{q}");
        assert!(q.ends_with("Type \"yes\" to turn it on: "), "{q}");
    }

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

    #[test]
    fn status_is_one_summary_line_then_the_backends_details_indented() {
        assert_eq!(status_lines(true, 3, "memory"), ["unlocked, 3 item(s), memory"]);
        assert_eq!(
            status_lines(false, 0, "bitwarden (me@example.org)\n2 duplicates\n1 item skipped"),
            ["locked, 0 item(s), bitwarden (me@example.org)", "  2 duplicates", "  1 item skipped"]
        );
        assert_eq!(status_lines(false, 1, "x\n"), ["locked, 1 item(s), x"], "no details, no extra lines");
    }

    /// A file the logs go into; `capture_logs` returns it.
    struct Captured {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
    }

    fn text(logs: &Captured) -> String {
        std::fs::read_to_string(&logs.path).unwrap()
    }

    /// Logs from here on go into the returned file until the guard is dropped.
    fn capture_logs() -> (Captured, tracing::subscriber::DefaultGuard) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let subscriber = tracing_subscriber::fmt()
            .with_writer(std::fs::File::create(&path).unwrap())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        (Captured { _dir: dir, path }, tracing::subscriber::set_default(subscriber))
    }

    #[test]
    fn each_failed_hardening_step_is_a_warning() {
        let (out, _guard) = capture_logs();
        log_hardening_failures(Vec::new());
        assert_eq!(text(&out), "", "nothing failed, nothing logged");
        log_hardening_failures(["PR_SET_DUMPABLE: boom".to_owned(), "RLIMIT_CORE: bang".to_owned()]);
        let text = text(&out);
        assert_eq!(text.matches("WARN").count(), 2, "{text}");
        assert!(text.contains("process hardening incomplete: PR_SET_DUMPABLE: boom"), "{text}");
        assert!(text.contains("process hardening incomplete: RLIMIT_CORE: bang"), "{text}");
    }

    #[test]
    fn a_pinentry_that_fails_the_check_is_refused_with_the_reason() {
        let trust = Trust::system().unwrap();
        let why = verify_pinentry(&trust, "/nonexistent/bwss-test/pinentry").unwrap_err();
        assert!(why.starts_with("pinentry /nonexistent/bwss-test/pinentry"), "{why}");
    }

    /// A daemon on a memory backend (password "pw"), unlocked, with no bus.
    async fn unlocked_daemon() -> (Arc<Daemon>, Arc<MemoryBackend>) {
        let backend = Arc::new(MemoryBackend::new("pw"));
        let prompter = Prompter::new("false", Duration::from_secs(1));
        let d = Daemon::new(Keyring::new(None, None), backend.clone(), prompter, config::Config::default());
        d.unlock_with_password("pw").await.unwrap();
        (d, backend)
    }

    #[tokio::test(start_paused = true)]
    async fn the_backend_is_pulled_every_period_and_not_before() {
        let (out, _guard) = capture_logs();
        let (d, backend) = unlocked_daemon().await;
        // A locked backend under an unlocked keyring makes every pull log a failure.
        backend.lock().await;
        let pulls = || text(&out).matches("refresh failed").count();
        let task = spawn_sync(d, Duration::from_secs(100));
        tokio::time::sleep(Duration::from_secs(99)).await;
        assert_eq!(pulls(), 0, "the first pull is one period after the start, not at once");
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(pulls(), 1);
        tokio::time::sleep(Duration::from_secs(100)).await;
        assert_eq!(pulls(), 2);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_keyring_is_locked_at_the_next_check() {
        let (d, _backend) = unlocked_daemon().await;
        let task = spawn_idle_lock(d.clone(), Duration::ZERO, Duration::from_secs(30));
        tokio::time::sleep(Duration::from_secs(31)).await;
        assert!(!d.keyring.lock().await.is_unlocked());
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_keyring_used_within_the_limit_stays_unlocked() {
        let (d, _backend) = unlocked_daemon().await;
        let task = spawn_idle_lock(d.clone(), Duration::from_secs(3600), Duration::from_secs(30));
        tokio::time::sleep(Duration::from_secs(300)).await;
        assert!(d.keyring.lock().await.is_unlocked());
        task.abort();
    }
}
