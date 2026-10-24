//! Locks the keyring when the machine sleeps or the session locks (TM-013).
//!
//! Two signals from systemd-logind on the system bus count:
//! `Manager.PrepareForSleep(true)` and the `Lock` signal of the session bwss
//! runs in. Without a system bus or without logind, bwss logs a warning and
//! goes on; idle locking does not depend on this.

use std::future::{Future, poll_fn};
use std::pin::Pin;

use zbus::export::futures_core::Stream;

const SERVICE: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_IFACE: &str = "org.freedesktop.login1.Session";

/// Connects to the system bus and calls `lock` on every sleep or screen lock,
/// for as long as the connection lives.
pub async fn run<F, Fut>(lock: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = ()>,
{
    run_with(zbus::connection::Builder::system(), lock).await
}

async fn run_with<F, Fut>(builder: zbus::connection::Builder<'_>, lock: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = ()>,
{
    match builder.build().await {
        Ok(conn) => watch(&conn, lock).await,
        Err(e) => tracing::warn!("no system bus, so no lock on sleep or screen lock: {e}"),
    }
}

/// The listener on an open connection to the bus logind is on.
pub async fn watch<F, Fut>(conn: &zbus::Connection, lock: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = ()>,
{
    if let Err(e) = listen(conn, &lock).await {
        tracing::warn!("cannot listen to logind, so no lock on sleep or screen lock: {e}");
    }
}

async fn listen<F, Fut>(conn: &zbus::Connection, lock: &F) -> zbus::Result<()>
where
    F: Fn() -> Fut,
    Fut: Future<Output = ()>,
{
    let manager = zbus::Proxy::new(conn, SERVICE, MANAGER_PATH, MANAGER_IFACE).await?;
    // Subscribe before the lookup, so no signal falls in between.
    let mut sleeps = manager.receive_signal("PrepareForSleep").await?;
    let mut locks = match current_session(&manager).await {
        Ok(path) => {
            let session = zbus::Proxy::new(conn, SERVICE, path, SESSION_IFACE).await?;
            Some(session.receive_signal("Lock").await?)
        }
        Err(e) => {
            tracing::warn!("no logind session, so no lock on screen lock (sleep still locks): {e}");
            None
        }
    };
    tracing::info!("locking on sleep{}", if locks.is_some() { " and screen lock" } else { "" });
    loop {
        tokio::select! {
            msg = next(&mut sleeps) => {
                let Some(msg) = msg else {
                    tracing::warn!("the logind connection closed, so sleep and screen lock no longer lock the keyring");
                    break;
                };
                if msg.body().deserialize::<bool>().is_ok_and(locks_on_sleep) {
                    tracing::info!("system is going to sleep");
                    lock().await;
                }
            }
            msg = async {
                match locks.as_mut() {
                    Some(s) => next(s).await,
                    None => std::future::pending().await,
                }
            } => {
                if msg.is_none() {
                    tracing::warn!("the logind session signal ended, so screen lock no longer locks the keyring");
                    locks = None;
                    continue;
                }
                tracing::info!("session lock requested");
                lock().await;
            }
        }
    }
    Ok(())
}

/// `PrepareForSleep(true)` locks; `PrepareForSleep(false)` is the wake-up.
fn locks_on_sleep(starting: bool) -> bool {
    starting
}

async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

/// The session bwss runs in: by process, then by `XDG_SESSION_ID`.
async fn current_session(manager: &zbus::Proxy<'_>) -> zbus::Result<zbus::OwnedObjectPath> {
    let by_pid: zbus::Result<zbus::OwnedObjectPath> = manager.call("GetSessionByPID", &(std::process::id(),)).await;
    match by_pid {
        Ok(path) => Ok(path),
        Err(e) => match session_id(std::env::var("XDG_SESSION_ID").ok()) {
            Some(id) => manager.call("GetSession", &(id,)).await,
            None => Err(e),
        },
    }
}

/// The session id to fall back to; an empty variable names nothing.
fn session_id(var: Option<String>) -> Option<String> {
    var.filter(|id| !id.is_empty())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn only_going_to_sleep_locks() {
        assert!(locks_on_sleep(true));
        assert!(!locks_on_sleep(false), "waking up must not lock");
    }

    #[test]
    fn the_session_id_fallback_ignores_an_unset_or_empty_variable() {
        assert_eq!(session_id(Some("2".into())).as_deref(), Some("2"));
        assert_eq!(session_id(Some(String::new())), None);
        assert_eq!(session_id(None), None);
    }

    #[tokio::test]
    async fn no_system_bus_returns_without_locking() {
        let locked = AtomicUsize::new(0);
        let builder = zbus::connection::Builder::address("unix:path=/nonexistent/bwss-test-bus");
        run_with(builder, || async {
            locked.fetch_add(1, Ordering::SeqCst);
        })
        .await;
        assert_eq!(locked.load(Ordering::SeqCst), 0);
    }
}
