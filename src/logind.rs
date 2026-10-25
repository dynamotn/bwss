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
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinSet;
use zbus::export::futures_core::Stream;
use zbus::names::OwnedUniqueName;

const SERVICE: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
const SESSIONS_PATH: &str = "/org/freedesktop/login1/session";
const SESSION_IFACE: &str = "org.freedesktop.login1.Session";

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
/// Locks the keyring.
type Lock = Arc<dyn Fn() -> BoxFuture<()> + Send + Sync>;
/// Reads the uid of the user of the session a `Lock` signal came from.
type UserOf = Arc<dyn Fn(zbus::Message) -> BoxFuture<zbus::Result<u32>> + Send + Sync>;
type Messages = Pin<Box<dyn Stream<Item = zbus::Message> + Send>>;
/// logind's unique name at every change of owner; `None` once it left the bus.
type OwnerChanges = Pin<Box<dyn Stream<Item = Option<OwnedUniqueName>> + Send>>;

/// Connects to the system bus and calls `lock` on every sleep or screen lock,
/// for as long as the connection lives.
pub async fn run<F, Fut>(lock: F)
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let lock: Lock = Arc::new(move || Box::pin(lock()));
    run_with(zbus::connection::Builder::system(), lock).await
}

async fn run_with(builder: zbus::connection::Builder<'_>, lock: Lock) {
    match builder.build().await {
        Ok(conn) => watch(&conn, lock).await,
        Err(e) => tracing::warn!("no system bus, so no lock on sleep or screen lock: {e}"),
    }
}

/// The listener on an open connection to the bus logind is on.
async fn watch(conn: &zbus::Connection, lock: Lock) {
    if let Err(e) = listen(conn, lock).await {
        tracing::warn!("cannot listen to logind, so no lock on sleep or screen lock: {e}");
    }
}

/// Subscribes to logind's signals, then hands them to `serve`.
///
/// Setting up waits for the bus, one reply at a time. zbus reads every reply
/// and every stream from one socket and stops at a full stream, so no reply
/// is awaited while a stream that any client can feed sits unread: the owner
/// changes come from the bus itself only, the lookups run before logind's
/// signals are subscribed to, and the sleep stream is read while the `Lock`
/// subscription waits for its reply.
async fn listen(conn: &zbus::Connection, lock: Lock) -> zbus::Result<()> {
    let bus = zbus::fdo::DBusProxy::new(conn).await?;
    // Subscribe before the lookup, so no change of owner falls in between.
    // zbus pins this stream to the bus itself, so no client can forge a change.
    let changes = bus.receive_name_owner_changed_with_args(&[(0, SERVICE)]).await?;
    let owner = match bus.get_name_owner(zbus::names::BusName::try_from(SERVICE)?).await {
        Ok(owner) => Some(owner),
        Err(e) => {
            tracing::warn!("cannot find logind on the bus, so session locks are ignored until it appears: {e}");
            None
        }
    };
    let manager = zbus::Proxy::new(conn, SERVICE, MANAGER_PATH, MANAGER_IFACE).await?;
    // Our own session if there is one, else every session of our user. Looked
    // up before subscribing to logind's signals: until `serve` reads them, a
    // flood of forged ones could fill their queue and stall these replies.
    let (scope, only_uid) = match current_session(&manager).await {
        Ok(path) => (Some(path.into_inner()), None),
        Err(e) => {
            tracing::warn!(
                "no logind session of our own, so the lock of any session of this user locks the keyring: {e}"
            );
            (None, Some(real_uid()))
        }
    };
    let mut sleeps: Messages = Box::pin(manager.receive_signal("PrepareForSleep").await?);
    let subscribe = zbus::MessageStream::for_match_rule(session_lock_rule(scope)?, conn, None);
    // A sleep stream that ended was logged, and nothing is left to listen to.
    let Some(locks) = while_draining(subscribe, &mut sleeps, &lock).await else { return Ok(()) };
    let locks = Signals(locks?);
    let session_conn = conn.clone();
    let user_of: UserOf = Arc::new(move |msg| {
        let conn = session_conn.clone();
        Box::pin(async move { session_user(&conn, &msg).await })
    });
    tracing::info!(
        "locking on sleep and screen lock{}",
        if only_uid.is_some() { " (of any session of this user)" } else { "" }
    );
    let listener = Listener {
        owner,
        owners: Box::pin(Owners(changes)),
        sleeps,
        locks: Box::pin(locks),
        only: only_uid.map(|uid| (uid, user_of)),
        lock,
    };
    let mut lookups = JoinSet::new();
    serve(listener, &mut lookups).await;
    // A lookup still running locks on its own if it has to.
    lookups.detach_all();
    Ok(())
}

/// Waits for `subscription` while reading `sleeps`, and locks on every sleep
/// meanwhile; `None` if the sleep stream ended first.
///
/// zbus reads every reply and every stream from one socket and stops at a
/// full stream, so a flood of forged sleep signals left unread would keep the
/// reply from ever arriving.
async fn while_draining<T>(subscription: impl Future<Output = T>, sleeps: &mut Messages, lock: &Lock) -> Option<T> {
    let mut subscription = std::pin::pin!(subscription);
    loop {
        tokio::select! {
            // The subscription first, so a steady flood cannot starve it.
            biased;
            done = &mut subscription => return Some(done),
            msg = next(sleeps) => {
                if !on_sleep(msg, lock).await {
                    return None;
                }
            }
        }
    }
}

/// Locks on `PrepareForSleep(true)`; `false` once the sleep stream ended
/// (`msg` is `None`).
async fn on_sleep(msg: Option<zbus::Message>, lock: &Lock) -> bool {
    let Some(msg) = msg else {
        tracing::warn!("the logind connection closed, so sleep and screen lock no longer lock the keyring");
        return false;
    };
    if msg.body().deserialize::<bool>().is_ok_and(locks_on_sleep) {
        tracing::info!("system is going to sleep");
        lock().await;
    }
    true
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

/// The new owner of logind's name at every `NameOwnerChanged` for it.
struct Owners(zbus::fdo::NameOwnerChangedStream);

impl Stream for Owners {
    type Item = Option<OwnedUniqueName>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_next(cx).map(|change| change.map(|change| new_owner(&change)))
    }
}

fn new_owner(change: &zbus::fdo::NameOwnerChanged) -> Option<OwnedUniqueName> {
    change.args().ok().and_then(|args| args.new_owner().as_ref().map(|name| name.to_owned().into()))
}

/// The uid of the user a session belongs to: the first field of its `User`
/// property, read from the session the signal came from.
async fn session_user(conn: &zbus::Connection, msg: &zbus::Message) -> zbus::Result<u32> {
    let path = msg.header().path().map(ToOwned::to_owned).ok_or(zbus::Error::MissingField)?;
    // One property is read once: no cache, so no GetAll and no subscription.
    let builder = zbus::proxy::Builder::new(conn).destination(SERVICE).path(path).interface(SESSION_IFACE);
    let session: zbus::Proxy<'_> = builder.cache_properties(zbus::proxy::CacheProperties::No).build().await?;
    let (uid, _user): (u32, zbus::OwnedObjectPath) = session.get_property("User").await?;
    Ok(uid)
}

/// What `serve` listens to and how it locks.
struct Listener {
    /// logind's unique name when listening started, if it had one.
    owner: Option<OwnedUniqueName>,
    owners: OwnerChanges,
    sleeps: Messages,
    locks: Messages,
    /// Without a session of our own: our uid, and how to read the user of a session.
    only: Option<(u32, UserOf)>,
    lock: Lock,
}

/// Calls `lock` on every sleep and on every session lock logind sent for us,
/// until the sleep stream ends (the connection to logind closed).
///
/// Nothing in this loop waits for the bus: zbus reads every stream and every
/// reply from one socket, and a stream left unread stops it (`listen` says
/// how setting up avoids that). The sender is compared with logind's name as
/// tracked from the bus, and the user of a session is read in a task in
/// `lookups`, which locks on its own.
async fn serve(listener: Listener, lookups: &mut JoinSet<()>) {
    let Listener { mut owner, owners, mut sleeps, locks, only, lock } = listener;
    let (mut owners, mut locks) = (Some(owners), Some(locks));
    let mut spoofs = SpoofLog::default();
    loop {
        // Forget the lookups that are done; none is waited for.
        while lookups.try_join_next().is_some() {}
        tokio::select! {
            // Owner changes first, so a Lock that arrived beside one is judged
            // by the new name; the other streams yield only logind's signals.
            biased;
            change = next_of(&mut owners) => match change {
                Some(Some(name)) => {
                    tracing::info!("logind has a new name on the bus: {name}");
                    owner = Some(name);
                }
                Some(None) => {
                    tracing::warn!("logind left the bus, so session locks are ignored until it comes back");
                    owner = None;
                }
                // The connection closed; the sleep stream ends too.
                None => owners = None,
            },
            msg = next(&mut sleeps) => {
                if !on_sleep(msg, &lock).await {
                    break;
                }
            }
            msg = next_of(&mut locks) => {
                let Some(msg) = msg else {
                    tracing::warn!("the logind session signal ended, so screen lock no longer locks the keyring");
                    locks = None;
                    continue;
                };
                // Without an owner, logind is gone, which was logged then.
                let Some(logind) = owner.as_ref() else { continue };
                if !sent_by(&msg, logind) {
                    if let Some(line) = spoofs.note(Instant::now()) {
                        tracing::warn!("{line}");
                    }
                    continue;
                }
                match &only {
                    None => {
                        tracing::info!("session lock requested");
                        lock().await;
                    }
                    Some((uid, user_of)) => {
                        lookups.spawn(lock_if_ours(msg, *uid, user_of.clone(), lock.clone()));
                    }
                }
            }
        }
    }
}

/// Whether `msg` came from the connection named `name`. A unicast signal
/// reaches us whatever match rule we added, so only its sender tells.
fn sent_by(msg: &zbus::Message, name: &OwnedUniqueName) -> bool {
    msg.header().sender().is_some_and(|sender| sender.as_str() == name.as_str())
}

/// Locks if the session `msg` came from belongs to `uid`, or if its user
/// cannot be read: logind sent the signal, so that fails closed.
async fn lock_if_ours(msg: zbus::Message, uid: u32, user_of: UserOf, lock: Lock) {
    let ours = match user_of(msg.clone()).await {
        Ok(session_uid) => session_uid == uid,
        Err(e) => {
            let header = msg.header();
            let path = header.path().map_or("", |path| path.as_str());
            tracing::warn!("cannot read the user of session {path}, so its lock locks the keyring: {e}");
            true
        }
    };
    if ours {
        tracing::info!("session lock requested");
        lock().await;
    }
}

/// How often a flood of signals not sent by logind is reported.
const SPOOF_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Rate-limits the warnings about `Lock` signals not sent by logind: the
/// first one, then at most one count per `SPOOF_REPORT_INTERVAL`.
#[derive(Default)]
struct SpoofLog {
    /// When the last warning was logged.
    last: Option<Instant>,
    /// The signals ignored since then.
    ignored: u64,
}

impl SpoofLog {
    /// Counts one more ignored signal at `now`, and returns the warning to log, if any.
    fn note(&mut self, now: Instant) -> Option<String> {
        self.ignored += 1;
        if self.last.is_some_and(|last| now.duration_since(last) < SPOOF_REPORT_INTERVAL) {
            return None;
        }
        let line = match self.last {
            None => "ignoring a Lock signal not sent by logind".to_owned(),
            Some(_) => format!("ignored {} Lock signals not sent by logind since the last warning", self.ignored),
        };
        self.last = Some(now);
        self.ignored = 0;
        Some(line)
    }
}

/// `PrepareForSleep(true)` locks; `PrepareForSleep(false)` is the wake-up.
fn locks_on_sleep(starting: bool) -> bool {
    starting
}

async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

/// The next item of `stream`; never, once it is gone.
async fn next_of<S: Stream + Unpin>(stream: &mut Option<S>) -> Option<S::Item> {
    match stream.as_mut() {
        Some(stream) => next(stream).await,
        None => std::future::pending().await,
    }
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
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const LOGIND: &str = ":1.3";
    const UID: u32 = 1000;

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

    #[test]
    fn spoofed_signals_are_reported_first_then_counted_once_a_minute() {
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let mut log = SpoofLog::default();
        assert_eq!(log.note(at(0)).as_deref(), Some("ignoring a Lock signal not sent by logind"));
        assert_eq!(log.note(at(1)), None);
        assert_eq!(log.note(at(59)), None);
        assert_eq!(
            log.note(at(60)).as_deref(),
            Some("ignored 3 Lock signals not sent by logind since the last warning"),
            "the two kept quiet and this one"
        );
        assert_eq!(log.note(at(119)), None, "a minute after the last warning, not the first");
        assert_eq!(
            log.note(at(180)).as_deref(),
            Some("ignored 2 Lock signals not sent by logind since the last warning")
        );
    }

    /// A `lock` callback and the count of its calls.
    fn counting() -> (Arc<AtomicUsize>, Lock) {
        let count = Arc::new(AtomicUsize::new(0));
        let calls = count.clone();
        let lock: Lock = Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::ready(()))
        });
        (count, lock)
    }

    /// Whose turn it is among the streams of a `Script`.
    #[derive(Clone, Default)]
    struct Turns(Arc<AtomicUsize>);

    /// One stream of a `Script`: it yields its next item only on that item's
    /// turn, so the items of all streams are handled in the order written,
    /// whatever the streams are polled in. An item `None` ends the stream;
    /// the sleep stream also ends after the last turn, `ends_after`, which
    /// ends `serve`.
    struct Part<T> {
        turns: Turns,
        items: VecDeque<(usize, Option<T>)>,
        ends_after: Option<usize>,
    }

    impl<T: Unpin> Stream for Part<T> {
        type Item = T;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<T>> {
            let turn = self.turns.0.load(Ordering::SeqCst);
            match self.items.front() {
                None if self.ends_after == Some(turn) => std::task::Poll::Ready(None),
                Some((at, _)) if *at == turn => {
                    self.turns.0.fetch_add(1, Ordering::SeqCst);
                    std::task::Poll::Ready(self.items.pop_front().and_then(|(_, item)| item))
                }
                // Not this stream's turn yet, or nothing more to come.
                _ => {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            }
        }
    }

    /// What the streams `serve` reads yield, in order.
    #[derive(Default)]
    struct Script {
        next: usize,
        owners: VecDeque<(usize, Option<Option<OwnedUniqueName>>)>,
        sleeps: VecDeque<(usize, Option<zbus::Message>)>,
        locks: VecDeque<(usize, Option<zbus::Message>)>,
    }

    impl Script {
        fn turn(&mut self) -> usize {
            self.next += 1;
            self.next - 1
        }

        /// logind's name changes to `owner` (`None`: it left the bus).
        fn owner(mut self, owner: Option<&str>) -> Self {
            let at = self.turn();
            self.owners.push_back((at, Some(owner.map(name))));
            self
        }

        fn owners_end(mut self) -> Self {
            let at = self.turn();
            self.owners.push_back((at, None));
            self
        }

        fn sleep(mut self, starting: bool) -> Self {
            let at = self.turn();
            self.sleeps.push_back((at, Some(sleep_signal(starting))));
            self
        }

        fn lock(mut self, msg: zbus::Message) -> Self {
            let at = self.turn();
            self.locks.push_back((at, Some(msg)));
            self
        }

        fn locks_end(mut self) -> Self {
            let at = self.turn();
            self.locks.push_back((at, None));
            self
        }

        /// Runs `serve` through the script, with `owner` as logind's name at the
        /// start and `only` as in `Listener`, until every item was handled and
        /// every lookup done; returns how often it locked.
        async fn serve(self, owner: Option<&str>, only: Option<(u32, UserOf)>) -> usize {
            let turns = Turns::default();
            let (count, lock) = counting();
            let listener = Listener {
                owner: owner.map(name),
                owners: Box::pin(Part { turns: turns.clone(), items: self.owners, ends_after: None }),
                sleeps: Box::pin(Part { turns: turns.clone(), items: self.sleeps, ends_after: Some(self.next) }),
                locks: Box::pin(Part { turns, items: self.locks, ends_after: None }),
                only,
                lock,
            };
            let mut lookups = JoinSet::new();
            serve(listener, &mut lookups).await;
            while lookups.join_next().await.is_some() {}
            count.load(Ordering::SeqCst)
        }
    }

    fn name(name: &str) -> OwnedUniqueName {
        OwnedUniqueName::try_from(name).unwrap()
    }

    fn sleep_signal(starting: bool) -> zbus::Message {
        zbus::Message::signal(MANAGER_PATH, MANAGER_IFACE, "PrepareForSleep").sender(LOGIND).build(&starting).unwrap()
    }

    /// The `Lock` of session `session`, sent by `sender` (none: no sender field).
    fn lock_signal(session: &str, sender: Option<&str>) -> zbus::Message {
        let builder = zbus::Message::signal(format!("{SESSIONS_PATH}/{session}"), SESSION_IFACE, "Lock");
        match sender {
            Some(sender) => builder.sender(sender),
            None => builder,
        }
        .build(&())
        .unwrap()
    }

    fn logind_lock(session: &str) -> zbus::Message {
        lock_signal(session, Some(LOGIND))
    }

    /// What a `Flood` and the subscription it holds back share: how many
    /// signals were read, and the subscription's waker.
    #[derive(Default)]
    struct Drained {
        read: AtomicUsize,
        waker: std::sync::Mutex<Option<std::task::Waker>>,
    }

    /// A sleep stream that yields `items`, then ends.
    struct Flood {
        items: VecDeque<zbus::Message>,
        drained: Arc<Drained>,
    }

    impl Stream for Flood {
        type Item = zbus::Message;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            match self.items.pop_front() {
                Some(msg) => {
                    self.drained.read.fetch_add(1, Ordering::SeqCst);
                    if let Some(waker) = self.drained.waker.lock().unwrap().take() {
                        waker.wake();
                    }
                    std::task::Poll::Ready(Some(msg))
                }
                None => std::task::Poll::Ready(None),
            }
        }
    }

    /// A subscription whose reply comes only once `signals` sleep signals were
    /// read, as zbus reads the reply only after it queued what came before.
    fn held_back(drained: Arc<Drained>, signals: usize) -> impl Future<Output = &'static str> {
        poll_fn(move |cx| {
            if drained.read.load(Ordering::SeqCst) >= signals {
                return std::task::Poll::Ready("subscribed");
            }
            *drained.waker.lock().unwrap() = Some(cx.waker().clone());
            std::task::Poll::Pending
        })
    }

    /// Subscribes with `while_draining` while `flood` comes in; returns the
    /// result, how many signals were read and how often it locked. The flood
    /// ends after its last signal. With the clock paused, a subscription that
    /// never resolves times out at once.
    async fn subscribe_through(flood: Vec<bool>, held_for: usize) -> (Option<Option<&'static str>>, usize, usize) {
        let drained = Arc::new(Drained::default());
        let items = flood.into_iter().map(sleep_signal).collect();
        let mut sleeps: Messages = Box::pin(Flood { items, drained: drained.clone() });
        let (count, lock) = counting();
        let subscription = held_back(drained.clone(), held_for);
        let result =
            tokio::time::timeout(Duration::from_secs(60), while_draining(subscription, &mut sleeps, &lock)).await;
        (result.ok(), drained.read.load(Ordering::SeqCst), count.load(Ordering::SeqCst))
    }

    #[tokio::test(start_paused = true)]
    async fn sleep_signals_are_drained_while_the_lock_subscription_waits() {
        // More than the 64 messages zbus queues for one stream.
        const SIGNALS: usize = 100;
        let flood = (0..SIGNALS).map(|i| i % 2 == 0).collect();
        let (result, read, locked) = subscribe_through(flood, SIGNALS).await;
        // The reply comes with the last signal, and is taken before the end of
        // the stream is seen.
        assert_eq!(result, Some(Some("subscribed")), "the subscription resolves once the flood was read");
        assert_eq!(read, SIGNALS, "every sleep signal was read");
        assert_eq!(locked, SIGNALS / 2, "PrepareForSleep(true) locks, (false) does not");
    }

    #[tokio::test(start_paused = true)]
    async fn a_sleep_stream_that_ends_during_the_subscription_ends_listening() {
        let (result, read, locked) = subscribe_through(vec![true], usize::MAX).await;
        assert_eq!(result, Some(None), "no subscription result once the sleep stream ended");
        assert_eq!((read, locked), (1, 1), "the sleep before the end still locked");
    }

    #[tokio::test]
    async fn no_system_bus_returns_without_locking() {
        let (count, lock) = counting();
        let builder = zbus::connection::Builder::address("unix:path=/nonexistent/bwss-test-bus");
        run_with(builder, lock).await;
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn going_to_sleep_locks_and_waking_up_does_not() {
        let locked = Script::default().sleep(false).sleep(true).serve(Some(LOGIND), None).await;
        assert_eq!(locked, 1, "PrepareForSleep(true) locks once, (false) never");
    }

    #[tokio::test]
    async fn only_a_session_lock_sent_by_logind_locks() {
        let script = Script::default()
            .lock(lock_signal("_32", Some(":1.66")))
            .lock(lock_signal("_32", None))
            .lock(logind_lock("_32"));
        assert_eq!(script.serve(Some(LOGIND), None).await, 1, "neither another client's Lock nor one without a sender");
    }

    #[tokio::test]
    async fn the_lock_of_logind_is_judged_by_its_name_as_it_changes() {
        let script = Script::default()
            // No owner at the start: logind's own name does not lock yet.
            .lock(logind_lock("_32"))
            .owner(Some(LOGIND))
            .lock(logind_lock("_32"))
            // logind left: its old name no longer locks.
            .owner(None)
            .lock(logind_lock("_32"))
            // logind came back under another name: only that one locks.
            .owner(Some(":1.9"))
            .lock(logind_lock("_32"))
            .lock(lock_signal("_32", Some(":1.9")))
            // The connection closed, as far as owner changes go.
            .owners_end()
            .lock(lock_signal("_32", Some(":1.9")));
        assert_eq!(script.serve(None, None).await, 3, "only the Locks of the name logind had then");
    }

    #[tokio::test]
    async fn sleep_still_locks_after_the_session_signal_ended() {
        let locked = Script::default().locks_end().sleep(true).serve(Some(LOGIND), None).await;
        assert_eq!(locked, 1, "sleep locks although screen lock no longer can");
    }

    #[tokio::test]
    async fn without_a_session_of_our_own_the_sessions_of_our_user_and_unreadable_ones_lock() {
        // _32 is ours, _99 another user's, and _77 has no user to read.
        let user_of: UserOf = Arc::new(|msg: zbus::Message| {
            let path = msg.header().path().map(ToString::to_string).unwrap_or_default();
            Box::pin(async move {
                match path.rsplit('/').next() {
                    Some("_32") => Ok(UID),
                    Some("_99") => Ok(UID + 1),
                    _ => Err(zbus::Error::MissingField),
                }
            })
        });
        let script = Script::default()
            .lock(logind_lock("_99"))
            .lock(logind_lock("_32"))
            .lock(logind_lock("_77"))
            .lock(lock_signal("_32", Some(":1.66")));
        let locked = script.serve(Some(LOGIND), Some((UID, user_of))).await;
        assert_eq!(locked, 2, "_32 and _77 lock, _99 and the spoof do not");
    }
}
