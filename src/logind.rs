//! Locks the keyring when the machine sleeps or the session locks (TM-013).
//!
//! Two signals from systemd-logind on the system bus count:
//! `Manager.PrepareForSleep(true)` and the `Lock` signal of the session bwss
//! runs in. A daemon outside any session (a systemd user unit) listens to
//! the `Lock` of every session instead, and locks for those of its own uid
//! only. Without a system bus or without logind, bwss logs a warning and
//! goes on; idle locking does not depend on this.

use std::future::{Future, poll_fn};
use std::pin::Pin;

use zbus::export::futures_core::Stream;

const SERVICE: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
const SESSIONS_PATH: &str = "/org/freedesktop/login1/session";
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
    // Our own session if there is one, else every session of our user.
    let (scope, only_uid) = match current_session(&manager).await {
        Ok(path) => (Some(path.into_inner()), None),
        Err(e) => {
            tracing::warn!(
                "no logind session of our own, so the lock of any session of this user locks the keyring: {e}"
            );
            (None, Some(real_uid()))
        }
    };
    let locks = Signals(zbus::MessageStream::for_match_rule(session_lock_rule(scope)?, conn, None).await?);
    let ours = |msg: zbus::Message| async move {
        match only_uid {
            None => true,
            Some(uid) => session_user(conn, &msg).await.is_ok_and(|session_uid| session_uid == uid),
        }
    };
    tracing::info!(
        "locking on sleep and screen lock{}",
        if only_uid.is_some() { " (of any session of this user)" } else { "" }
    );
    serve(sleeps, Some(locks), &ours, lock).await;
    Ok(())
}

/// The real uid of this process. logind exists on Linux only, so elsewhere no
/// session can be ours.
#[cfg(target_os = "linux")]
fn real_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

#[cfg(not(target_os = "linux"))]
fn real_uid() -> u32 {
    u32::MAX
}

/// Matches the `Lock` signal of `session`, or of every session without one.
fn session_lock_rule(session: Option<zbus::ObjectPath<'_>>) -> zbus::Result<zbus::MatchRule<'_>> {
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(SERVICE)
        .interface(SESSION_IFACE)
        .member("Lock");
    match session {
        Some(path) => rule.path(path),
        None => rule.path_namespace(SESSIONS_PATH),
    }
    .build()
}

/// The messages of a match rule; a bus error ends the stream.
struct Signals(zbus::MessageStream);

impl Stream for Signals {
    type Item = zbus::Message;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_next(cx).map(|item| item.and_then(Result::ok))
    }
}

/// The uid of the user a session belongs to: the first field of its `User`
/// property, read from the session the signal came from.
async fn session_user(conn: &zbus::Connection, msg: &zbus::Message) -> zbus::Result<u32> {
    let path = msg.header().path().map(ToOwned::to_owned).ok_or(zbus::Error::MissingField)?;
    // One property is read once: no cache, so no GetAll and no subscription.
    let session: zbus::Proxy<'_> = zbus::proxy::Builder::new(conn)
        .destination(SERVICE)
        .path(path)
        .interface(SESSION_IFACE)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await?;
    let (uid, _user): (u32, zbus::OwnedObjectPath) = session.get_property("User").await?;
    Ok(uid)
}

/// Calls `lock` on every sleep and on every session lock `ours` accepts,
/// until the sleep stream ends (the connection to logind closed).
async fn serve<S, L, O, OFut, F, Fut>(mut sleeps: S, mut locks: Option<L>, ours: &O, lock: &F)
where
    S: Stream<Item = zbus::Message> + Unpin,
    L: Stream<Item = zbus::Message> + Unpin,
    O: Fn(zbus::Message) -> OFut,
    OFut: Future<Output = bool>,
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
                let Some(msg) = msg else {
                    tracing::warn!("the logind session signal ended, so screen lock no longer locks the keyring");
                    locks = None;
                    continue;
                };
                if ours(msg).await {
                    tracing::info!("session lock requested");
                    lock().await;
                }
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

    fn any_session(_: zbus::Message) -> std::future::Ready<bool> {
        std::future::ready(true)
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
        serve(sleeps, None::<Items>, &any_session, &counting(&locked)).await;
        assert_eq!(locked.load(Ordering::SeqCst), 1, "PrepareForSleep(true) locks once, (false) never");
    }

    #[tokio::test]
    async fn a_session_lock_signal_locks() {
        let locked = AtomicUsize::new(0);
        // The connection closes (the sleep stream ends) only after a yield,
        // so the lock signal is certainly handled first, on every run.
        let sleeps = Items::new([], true);
        serve(sleeps, Some(Items::new([session_lock_signal()], false)), &any_session, &counting(&locked)).await;
        assert_eq!(locked.load(Ordering::SeqCst), 1, "Session.Lock locks once");
    }

    #[tokio::test]
    async fn a_session_lock_signal_that_is_not_ours_does_not_lock() {
        let locked = AtomicUsize::new(0);
        let sleeps = Items::new([], true);
        let locks = Items::new([session_lock_signal(), session_lock_signal()], false);
        let seen = AtomicUsize::new(0);
        // Rejects the first signal and accepts the second.
        let ours = |_: zbus::Message| std::future::ready(seen.fetch_add(1, Ordering::SeqCst) == 1);
        serve(sleeps, Some(locks), &ours, &counting(&locked)).await;
        assert_eq!(seen.load(Ordering::SeqCst), 2, "both signals are judged");
        assert_eq!(locked.load(Ordering::SeqCst), 1, "only the accepted one locks");
    }

    #[tokio::test]
    async fn sleep_still_locks_after_the_session_signal_ended() {
        let locked = AtomicUsize::new(0);
        // The sleep signal arrives only after a yield, so the (already ended)
        // session stream is certainly seen first, on every run.
        let sleeps = Items::new([sleep_signal(true)], true);
        serve(sleeps, Some(Items::new([], false)), &any_session, &counting(&locked)).await;
        assert_eq!(locked.load(Ordering::SeqCst), 1, "sleep locks although screen lock no longer can");
    }
}
