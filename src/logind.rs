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
    let sleeps = manager.receive_signal("PrepareForSleep").await?;
    let locks = match current_session(&manager).await {
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
    serve(sleeps, locks, lock).await;
    Ok(())
}

/// Calls `lock` on every sleep and every session lock, until the sleep
/// stream ends (the connection to logind closed).
async fn serve<S, L, F, Fut>(mut sleeps: S, mut locks: Option<L>, lock: &F)
where
    S: Stream<Item = zbus::Message> + Unpin,
    L: Stream<Item = zbus::Message> + Unpin,
    F: Fn() -> Fut,
    Fut: Future<Output = ()>,
{
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
#[expect(clippy::unwrap_used, reason = "tests")]
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

    /// A `lock` callback that counts its calls.
    fn counting(count: &AtomicUsize) -> impl Fn() -> std::future::Ready<()> + '_ {
        move || {
            count.fetch_add(1, Ordering::SeqCst);
            std::future::ready(())
        }
    }

    /// A stream of ready `items`, which then ends. With `after_yield`, the
    /// first poll is pending once, so another stream is polled before it.
    struct Items {
        items: std::collections::VecDeque<zbus::Message>,
        pending_once: bool,
    }

    impl Items {
        fn new(items: impl IntoIterator<Item = zbus::Message>, after_yield: bool) -> Self {
            Items { items: items.into_iter().collect(), pending_once: after_yield }
        }
    }

    impl Stream for Items {
        type Item = zbus::Message;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
            if std::mem::take(&mut self.pending_once) {
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            std::task::Poll::Ready(self.items.pop_front())
        }
    }

    fn sleep_signal(starting: bool) -> zbus::Message {
        zbus::Message::signal(MANAGER_PATH, MANAGER_IFACE, "PrepareForSleep").build(&starting).unwrap()
    }

    fn session_lock_signal() -> zbus::Message {
        zbus::Message::signal("/org/freedesktop/login1/session/_32", SESSION_IFACE, "Lock").build(&()).unwrap()
    }

    #[tokio::test]
    async fn no_system_bus_returns_without_locking() {
        let locked = AtomicUsize::new(0);
        let builder = zbus::connection::Builder::address("unix:path=/nonexistent/bwss-test-bus");
        run_with(builder, counting(&locked)).await;
        assert_eq!(locked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn going_to_sleep_locks_and_waking_up_does_not() {
        let locked = AtomicUsize::new(0);
        let sleeps = Items::new([sleep_signal(false), sleep_signal(true)], false);
        serve(sleeps, None::<Items>, &counting(&locked)).await;
        assert_eq!(locked.load(Ordering::SeqCst), 1, "PrepareForSleep(true) locks once, (false) never");
    }

    #[tokio::test]
    async fn a_session_lock_signal_locks() {
        let locked = AtomicUsize::new(0);
        // The connection closes (the sleep stream ends) only after a yield,
        // so the lock signal is certainly handled first, on every run.
        let sleeps = Items::new([], true);
        serve(sleeps, Some(Items::new([session_lock_signal()], false)), &counting(&locked)).await;
        assert_eq!(locked.load(Ordering::SeqCst), 1, "Session.Lock locks once");
    }

    #[tokio::test]
    async fn sleep_still_locks_after_the_session_signal_ended() {
        let locked = AtomicUsize::new(0);
        // The sleep signal arrives only after a yield, so the (already ended)
        // session stream is certainly seen first, on every run.
        let sleeps = Items::new([sleep_signal(true)], true);
        serve(sleeps, Some(Items::new([], false)), &counting(&locked)).await;
        assert_eq!(locked.load(Ordering::SeqCst), 1, "sleep locks although screen lock no longer can");
    }
}
