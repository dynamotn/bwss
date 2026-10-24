//! Shared daemon state and the operations behind the D-Bus objects.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use zbus::{Connection, OwnedObjectPath, message::Header, object_server::SignalEmitter};
use zeroize::Zeroizing;

use crate::acl::{CallerKind, Identities};
use crate::acl_confirm::{ConfirmSet, Mark};
use crate::backend::{AclTrust, Backend, BackendError};
use crate::config::{AclMode, Config};
use crate::dbus::{CollectionObj, ItemObj, ServiceObj};
use crate::keyring::{Diff, Keyring};
use crate::model::{Attributes, ItemData, LOGIN_COLLECTION, SESSION_COLLECTION, escape_segment, now, unescape_segment};
use crate::prompter::{Confirm, Prompter};
use crate::session::Session;
use crate::sync::lock;

pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
pub const DEFAULT_ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";

pub fn collection_path(id: &str) -> String {
    format!("{SERVICE_PATH}/collection/{}", escape_segment(id))
}

pub fn item_path(collection: &str, id: &str) -> String {
    format!("{SERVICE_PATH}/collection/{}/{}", escape_segment(collection), escape_segment(id))
}

#[expect(clippy::expect_used, reason = "callers pass only paths built from constants and escaped segments")]
pub fn op(path: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(path.to_owned()).expect("valid object path")
}

pub fn no_prompt() -> OwnedObjectPath {
    op("/")
}

/// Splits an object path into (collection, item).
pub fn parse_path(path: &str) -> Option<(String, Option<String>)> {
    if path == DEFAULT_ALIAS_PATH {
        return Some((LOGIN_COLLECTION.into(), None));
    }
    let rest = path.strip_prefix(&format!("{SERVICE_PATH}/collection/"))?;
    let mut parts = rest.split('/');
    let c = unescape_segment(parts.next().filter(|s| !s.is_empty())?)?;
    let i = match parts.next() {
        Some(seg) => Some(unescape_segment(seg)?),
        None => None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((c, i))
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum SecretError {
    #[zbus(error)]
    ZBus(zbus::Error),
    IsLocked(String),
    NoSession(String),
    NoSuchObject(String),
    NotSupported(String),
    AccessDenied(String),
    Failed(String),
}

impl From<BackendError> for SecretError {
    fn from(e: BackendError) -> Self {
        match e {
            BackendError::Locked => SecretError::IsLocked(e.to_string()),
            BackendError::Conflict(why) => {
                tracing::info!("write refused: {why}");
                SecretError::Failed("the secret was changed elsewhere; try again".into())
            }
            other => SecretError::Failed(other.to_string()),
        }
    }
}

/// The keyring locked while a write was in flight. The backend has already
/// stored the item, so the next unlock shows it.
fn locked_during_write() -> SecretError {
    SecretError::IsLocked("the keyring was locked during the write".into())
}

pub type SResult<T> = Result<T, SecretError>;

/// The attributes an app set: derived ones (`bwss:*`, design §3.2) left out.
fn own_attributes(a: &Attributes) -> Attributes {
    a.iter().filter(|(k, _)| !k.starts_with("bwss:")).map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// What a secret looks like on the wire: (session, parameters, value, content type).
pub type WireSecret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// What a client asked to store.
pub struct NewItem {
    pub label: String,
    pub attributes: Attributes,
    pub secret: Zeroizing<Vec<u8>>,
    pub content_type: String,
    pub replace: bool,
}

/// Most sessions one bus client may hold; its oldest one goes first.
pub const SESSIONS_PER_OWNER: usize = 64;
/// Most sessions held by all clients together; beyond it, departed clients are
/// reaped and then the busiest client loses its oldest session.
pub const SESSIONS_TOTAL: usize = 4096;
/// How long a failed remote password attempt delays the next one.
pub const FAILED_UNLOCK_DELAY: Duration = Duration::from_secs(2);
/// Most outstanding prompt objects one bus client may hold.
pub const PROMPTS_PER_OWNER: usize = 16;

/// The oldest of one client's objects (by their creation sequence number) when
/// it already holds `cap` of them and so has to give one up for a new one.
pub fn oldest_to_evict(seqs: impl IntoIterator<Item = u64>, cap: usize) -> Option<u64> {
    let mut count = 0usize;
    let mut oldest: Option<u64> = None;
    for seq in seqs {
        count += 1;
        oldest = Some(oldest.map_or(seq, |o| o.min(seq)));
    }
    if count >= cap { oldest } else { None }
}

/// What registering one more prompt for a client has to do.
#[derive(Debug, PartialEq, Eq)]
pub enum PromptSlot {
    Free,
    /// Dismiss the prompt with this sequence number first.
    Evict(u64),
    /// Every prompt of the client is already running: refuse the new one.
    Full,
}

/// Decides about a new prompt for a client holding `held` prompts, each as
/// (sequence number, cannot be dismissed: running or not yet registered).
/// Only the others may be dismissed, the oldest of those first.
pub fn prompt_slot(held: impl IntoIterator<Item = (u64, bool)>, cap: usize) -> PromptSlot {
    let held: Vec<_> = held.into_iter().collect();
    if held.len() < cap {
        return PromptSlot::Free;
    }
    match oldest_to_evict(held.iter().filter(|(_, running)| !running).map(|(seq, _)| *seq), 1) {
        Some(seq) => PromptSlot::Evict(seq),
        None => PromptSlot::Full,
    }
}

/// The client holding the most of the given sessions (ties: the lowest name).
pub fn fattest_owner<'a>(owners: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for o in owners {
        *counts.entry(o).or_default() += 1;
    }
    counts.into_iter().max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(a.0))).map(|(o, _)| o)
}

/// An outstanding prompt object.
pub struct PromptEntry {
    pub seq: u64,
    pub path: String,
    pub owner: String,
    /// `Prompt` was called: the action is running and cannot be dismissed.
    pub started: bool,
    /// The object is on the bus. Until then the entry only reserves a slot.
    pub registered: bool,
}

impl PromptEntry {
    /// Only a registered prompt that has not started can be dismissed.
    pub fn pinned(&self) -> bool {
        self.started || !self.registered
    }
}

/// The state of the caller's line in an item's ACL, on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Line {
    /// The caller is not listed.
    Absent,
    /// Listed and granted or confirmed on this device.
    Confirmed,
    /// Listed, and the user refused the line on this device.
    Denied,
    /// Listed, but synced in and not yet confirmed here.
    Unconfirmed,
}

/// How an access request is settled (design §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    /// Ask the user; "Always allow" is offered only when `always`.
    Ask {
        always: bool,
    },
    /// Ask once whether a line that synced in counts on this device.
    ConfirmLine,
}

/// The decision for a caller of `kind` whose line is in state `line`, when
/// the ACL applies at all. Unknown callers and interpreters are always
/// asked, never offered "Always allow", and no line ever counts for them.
pub fn decide(kind: CallerKind, line: Line) -> Decision {
    match (kind, line) {
        (CallerKind::Unknown | CallerKind::Interpreter, _) => Decision::Ask { always: false },
        (CallerKind::App, Line::Confirmed) => Decision::Allow,
        (CallerKind::App, Line::Denied) => Decision::Deny,
        (CallerKind::App, Line::Unconfirmed) => Decision::ConfirmLine,
        (CallerKind::App, Line::Absent) => Decision::Ask { always: true },
    }
}

/// The text of an access prompt, saying why "Always allow" is missing when it is.
fn ask_text(caller: &str, action: &str, label: &str, kind: CallerKind) -> String {
    let why = match kind {
        CallerKind::Unknown => "\n\nbwss cannot tell which application this is, so it asks every time.",
        CallerKind::Interpreter => {
            "\n\nThis program runs scripts and bwss cannot tell them apart, so it asks every time."
        }
        CallerKind::App => "",
    };
    format!("{caller}\n\nwants to {action} the keyring item\n\n\"{label}\"{why}")
}

/// The text of the one-time question about a line that synced in.
fn confirm_line_text(caller: &str, action: &str, label: &str) -> String {
    format!(
        "Allow {caller}, granted on another device?\n\nIt wants to {action} the keyring item\n\n\"{label}\"\n\n\
         This is asked once on this device; a denial is remembered."
    )
}

pub struct OpenSession {
    pub seq: u64,
    pub owner: String,
    pub session: Session,
}

pub struct Daemon {
    pub keyring: Mutex<Keyring>,
    pub backend: Arc<dyn Backend>,
    pub prompter: Prompter,
    pub config: Config,
    conn: OnceLock<Connection>,
    pub sessions: std::sync::Mutex<HashMap<String, Arc<OpenSession>>>,
    /// Outstanding prompt objects.
    pub prompts: std::sync::Mutex<Vec<PromptEntry>>,
    registered: Mutex<BTreeSet<String>>,
    counter: AtomicU64,
    last_activity: std::sync::Mutex<Instant>,
    /// Only one interactive unlock (and one access prompt) at a time.
    unlock_gate: Mutex<()>,
    /// Serializes remote password attempts and spaces out the failed ones.
    failure_gate: Mutex<()>,
    confirm_gate: Mutex<()>,
    /// The processes behind the bus names that called.
    identities: Identities,
    /// Where this device's ACL confirmations are kept (`None`: memory only).
    acl_state_path: OnceLock<PathBuf>,
    /// This device's ACL confirmations; loaded on first use after an unlock,
    /// dropped at lock with the key that seals them.
    confirmed: Mutex<Option<ConfirmSet>>,
}

impl Daemon {
    pub fn new(keyring: Keyring, backend: Arc<dyn Backend>, prompter: Prompter, config: Config) -> Arc<Self> {
        Arc::new(Daemon {
            keyring: Mutex::new(keyring),
            backend,
            prompter,
            config,
            conn: OnceLock::new(),
            sessions: std::sync::Mutex::new(HashMap::new()),
            prompts: std::sync::Mutex::new(Vec::new()),
            registered: Mutex::new(BTreeSet::new()),
            counter: AtomicU64::new(1),
            last_activity: std::sync::Mutex::new(Instant::now()),
            unlock_gate: Mutex::new(()),
            failure_gate: Mutex::new(()),
            confirm_gate: Mutex::new(()),
            identities: Identities::default(),
            acl_state_path: OnceLock::new(),
            confirmed: Mutex::new(None),
        })
    }

    pub fn set_connection(&self, conn: Connection) {
        let _ = self.conn.set(conn);
    }

    /// Keeps this device's ACL confirmations in `path` instead of memory.
    pub fn set_acl_state_path(&self, path: PathBuf) {
        let _ = self.acl_state_path.set(path);
    }

    /// The executable behind the sender of `header`, or `acl::UNKNOWN`.
    pub async fn caller(&self, header: &Header<'_>) -> String {
        self.identities.caller_executable(self.conn(), header).await
    }

    #[expect(clippy::expect_used, reason = "set_connection runs before the first request is served")]
    pub fn conn(&self) -> &Connection {
        self.conn.get().expect("connection set at startup")
    }

    pub fn next_id(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }

    pub fn touch(&self) {
        *lock(&self.last_activity) = Instant::now();
    }

    pub fn idle_for(&self) -> Duration {
        lock(&self.last_activity).elapsed()
    }

    pub fn session(&self, path: &str, caller: Option<&str>) -> SResult<Arc<OpenSession>> {
        let sessions = lock(&self.sessions);
        let s = sessions.get(path).ok_or_else(|| SecretError::NoSession(format!("no session {path}")))?;
        if caller.is_some_and(|c| c != s.owner) {
            return Err(SecretError::NoSession("the session belongs to another client".into()));
        }
        Ok(s.clone())
    }

    // --- object tree ---------------------------------------------------------

    /// Makes the exported objects match the keyring.
    pub async fn sync_objects(self: &Arc<Self>) -> zbus::Result<()> {
        let (collections, items) = {
            let k = self.keyring.lock().await;
            (k.collections().map(|c| c.id.clone()).collect::<Vec<_>>(), k.item_refs())
        };
        let mut wanted: BTreeSet<String> = BTreeSet::new();
        wanted.insert(DEFAULT_ALIAS_PATH.into());
        for c in &collections {
            wanted.insert(collection_path(c));
        }
        for (c, i) in &items {
            wanted.insert(item_path(c, i));
        }
        let server = self.conn().object_server();
        let mut registered = self.registered.lock().await;
        for path in registered.difference(&wanted).cloned().collect::<Vec<_>>() {
            match parse_path(&path) {
                Some((_, Some(_))) => {
                    server.remove::<ItemObj, _>(path.as_str()).await?;
                }
                _ => {
                    server.remove::<CollectionObj, _>(path.as_str()).await?;
                }
            }
            registered.remove(&path);
        }
        for path in wanted.difference(&registered.clone()).cloned().collect::<Vec<_>>() {
            match parse_path(&path) {
                Some((_, Some(i))) => {
                    server.at(path.as_str(), ItemObj { daemon: self.clone(), id: i }).await?;
                }
                Some((c, None)) => {
                    server.at(path.as_str(), CollectionObj { daemon: self.clone(), id: c }).await?;
                }
                None => continue,
            }
            registered.insert(path);
        }
        Ok(())
    }

    /// Updates exported objects and tells clients what changed.
    pub async fn publish(self: &Arc<Self>, diff: Diff) {
        // No bus yet (tests): nothing to export or signal.
        let Some(conn) = self.conn.get() else { return };
        if let Err(e) = self.sync_objects().await {
            tracing::warn!("could not update D-Bus objects: {e}");
        }
        let service = SignalEmitter::new(conn, SERVICE_PATH).ok();
        for c in &diff.collections_created {
            if let Some(s) = &service {
                let _ = ServiceObj::collection_created(s, op(&collection_path(c))).await;
            }
        }
        for c in &diff.collections_deleted {
            if let Some(s) = &service {
                let _ = ServiceObj::collection_deleted(s, op(&collection_path(c))).await;
            }
        }
        for (list, kind) in [(&diff.created, 0), (&diff.changed, 1), (&diff.deleted, 2)] {
            for (c, i) in list.iter() {
                let Ok(e) = SignalEmitter::new(conn, collection_path(c)) else { continue };
                let path = op(&item_path(c, i));
                let _ = match kind {
                    0 => CollectionObj::item_created(&e, path).await,
                    1 => CollectionObj::item_changed(&e, path).await,
                    _ => CollectionObj::item_deleted(&e, path).await,
                };
            }
        }
    }

    // --- locking ---------------------------------------------------------------

    pub async fn unlock_with_password(self: &Arc<Self>, password: &str) -> Result<(), BackendError> {
        let snap = self.backend.unlock(password).await?;
        let diff = self.keyring.lock().await.load(snap);
        self.touch();
        self.publish(diff).await;
        tracing::info!("keyring unlocked");
        Ok(())
    }

    /// Like `unlock_with_password` for remote callers: password attempts take
    /// turns and a failed one makes the next wait 2 s. This is a speed bump
    /// against processes of the same user, and the penalty does not hold `unlock_gate`,
    /// so the interactive unlock is never queued behind the penalty.
    pub async fn unlock_with_password_throttled(self: &Arc<Self>, password: &str) -> Result<(), BackendError> {
        let _turn = self.failure_gate.lock().await;
        // The gate is held for the attempt only, never for the penalty, and it
        // keeps this from running at the same time as the interactive unlock.
        let result = {
            let _gate = self.unlock_gate.lock().await;
            self.unlock_with_password(password).await
        };
        if result.is_err() {
            tokio::time::sleep(FAILED_UNLOCK_DELAY).await;
        }
        result
    }

    /// `unlock_interactive` for remote callers (`bwss unlock`): requests take
    /// the same turns as password attempts, and one that ends locked makes the
    /// next wait, so a client cannot keep a pinentry dialog in the user's face.
    pub async fn unlock_interactive_throttled(self: &Arc<Self>) -> bool {
        let _turn = self.failure_gate.lock().await;
        let unlocked = self.unlock_interactive().await;
        if !unlocked {
            tokio::time::sleep(FAILED_UNLOCK_DELAY).await;
        }
        unlocked
    }

    /// Adds a session, first making room under the per-client cap. At the
    /// global cap it does not add it unless `force`, which then closes the
    /// oldest session of the client holding the most. Returns the paths of the
    /// sessions that were dropped and whether the new one was added.
    pub fn admit_session(&self, open: Arc<OpenSession>, path: &str, force: bool) -> (Vec<String>, bool) {
        let mut sessions = lock(&self.sessions);
        let mut dropped = Vec::new();
        let mut drop_oldest_of = |sessions: &mut HashMap<String, Arc<OpenSession>>, owner: &str, cap: usize| {
            let mine = sessions.iter().filter(|(_, s)| s.owner == owner).map(|(p, s)| (s.seq, p.clone()));
            if let Some(oldest) = oldest_to_evict(mine.clone().map(|(seq, _)| seq), cap)
                && let Some((_, p)) = mine.clone().find(|(seq, _)| *seq == oldest)
            {
                sessions.remove(&p);
                dropped.push(p);
            }
        };
        drop_oldest_of(&mut sessions, &open.owner, SESSIONS_PER_OWNER);
        if sessions.len() >= SESSIONS_TOTAL {
            if !force {
                return (dropped, false);
            }
            let fattest = fattest_owner(sessions.values().map(|s| s.owner.as_str())).map(str::to_owned);
            if let Some(owner) = fattest {
                drop_oldest_of(&mut sessions, &owner, 1);
            }
        }
        sessions.insert(path.to_owned(), open);
        (dropped, true)
    }

    /// Unique bus names that hold sessions or prompts.
    pub fn known_owners(&self) -> BTreeSet<String> {
        let sessions = lock(&self.sessions);
        let prompts = lock(&self.prompts);
        sessions.values().map(|s| s.owner.clone()).chain(prompts.iter().map(|p| p.owner.clone())).collect()
    }

    /// Frees everything a client held, once it left the bus. Prompts that
    /// have not started drop their pending secret with their object.
    pub async fn drop_owner(&self, owner: &str) {
        self.identities.forget(owner);
        let sessions: Vec<String> = {
            let mut sessions = lock(&self.sessions);
            let paths: Vec<String> =
                sessions.iter().filter(|(_, s)| s.owner == owner).map(|(p, _)| p.clone()).collect();
            for p in &paths {
                sessions.remove(p);
            }
            paths
        };
        let prompts: Vec<String> = {
            let mut prompts = lock(&self.prompts);
            let paths = prompts.iter().filter(|p| p.owner == owner).map(|p| p.path.clone()).collect();
            prompts.retain(|p| p.owner != owner);
            paths
        };
        let server = self.conn().object_server();
        for p in sessions {
            let _ = server.remove::<crate::dbus::SessionObj, _>(p.as_str()).await;
        }
        for p in prompts {
            let _ = server.remove::<crate::dbus::PromptObj, _>(p.as_str()).await;
        }
    }

    /// Drops the sessions and prompts of every client no longer on the bus.
    pub async fn reap_departed(&self) {
        let Ok(bus) = zbus::fdo::DBusProxy::new(self.conn()).await else { return };
        for owner in self.known_owners() {
            let Ok(name) = zbus::names::BusName::try_from(owner.as_str()) else { continue };
            if matches!(bus.name_has_owner(name).await, Ok(false)) {
                self.drop_owner(&owner).await;
            }
        }
    }

    /// Asks for the master password; returns false when the user gave up.
    pub async fn unlock_interactive(self: &Arc<Self>) -> bool {
        let _gate = self.unlock_gate.lock().await;
        if self.keyring.lock().await.is_unlocked() {
            return true;
        }
        let mut error: Option<String> = None;
        for _ in 0..3 {
            let description = match self.config.backend {
                crate::config::BackendKind::Bitwarden => {
                    format!(
                        "An application wants to use your keyring.\n\nEnter the Bitwarden master password for {}.",
                        self.config.email
                    )
                }
                crate::config::BackendKind::Memory => "An application wants to use your keyring.".to_owned(),
            };
            let password = match self.prompter.password(&description, error.as_deref()).await {
                Ok(Some(p)) => p,
                Ok(None) => return false,
                Err(e) => {
                    tracing::warn!("prompt failed: {e}");
                    return false;
                }
            };
            match self.unlock_with_password(&password).await {
                Ok(()) => return true,
                Err(BackendError::WrongPassword) => error = Some("Wrong password, try again.".into()),
                Err(e) => error = Some(e.to_string()),
            }
        }
        false
    }

    pub async fn lock(self: &Arc<Self>) {
        let before: Vec<(String, String)>;
        {
            let mut k = self.keyring.lock().await;
            if !k.is_unlocked() {
                return;
            }
            before = k.item_refs();
            k.lock();
        }
        *self.confirmed.lock().await = None;
        self.backend.lock().await;
        let after: BTreeSet<(String, String)> = self.keyring.lock().await.item_refs().into_iter().collect();
        let diff = Diff { deleted: before.into_iter().filter(|r| !after.contains(r)).collect(), ..Default::default() };
        self.publish(diff).await;
        tracing::info!("keyring locked");
    }

    pub async fn refresh(self: &Arc<Self>) {
        if !self.keyring.lock().await.is_unlocked() {
            return;
        }
        match self.backend.refresh().await {
            Ok(Some(snap)) => {
                let diff = self.keyring.lock().await.load(snap);
                self.publish(diff).await;
            }
            Ok(None) => {}
            Err(e) => tracing::debug!("refresh failed: {e}"),
        }
    }

    // --- access control -------------------------------------------------------------

    /// Checks that `caller` may use the item, asking the user when needed.
    pub async fn authorize(self: &Arc<Self>, caller: &str, item_id: &str, action: &str) -> SResult<()> {
        let (mut decision, mut label) = self.decision(caller, item_id).await?;
        let _gate = match decision {
            Decision::Allow | Decision::Deny => None,
            Decision::Ask { .. } | Decision::ConfirmLine => {
                let gate = self.confirm_gate.lock().await;
                // An earlier prompt may have settled it meanwhile.
                (decision, label) = self.decision(caller, item_id).await?;
                Some(gate)
            }
        };
        let denied = || SecretError::AccessDenied(format!("{caller} was denied access to \"{label}\""));
        match decision {
            Decision::Allow => Ok(()),
            Decision::Deny => Err(denied()),
            Decision::ConfirmLine => {
                let answer = self.ask(&confirm_line_text(caller, action, &label), false).await;
                let allowed = answer != Confirm::Deny;
                self.remember(item_id, caller, if allowed { Mark::Confirmed } else { Mark::Denied }).await;
                if allowed { Ok(()) } else { Err(denied()) }
            }
            Decision::Ask { always } => {
                let text = ask_text(caller, action, &label, crate::acl::kind(caller));
                match self.ask(&text, always).await {
                    Confirm::Deny => Err(denied()),
                    Confirm::Always if always => {
                        self.grant(caller, item_id).await;
                        Ok(())
                    }
                    Confirm::Once | Confirm::Always => Ok(()),
                }
            }
        }
    }

    async fn ask(&self, text: &str, offer_always: bool) -> Confirm {
        self.prompter.confirm(text, offer_always).await.unwrap_or_else(|e| {
            tracing::warn!("prompt failed: {e}");
            Confirm::Deny
        })
    }

    /// The decision for `caller` on the item, and the item's label.
    async fn decision(&self, caller: &str, item_id: &str) -> SResult<(Decision, String)> {
        let (label, listed, collection) = {
            let k = self.keyring.lock().await;
            let item = k.item(item_id).ok_or_else(|| SecretError::IsLocked("the item is locked".into()))?;
            (item.label.clone(), item.acl.iter().any(|a| a == caller), item.collection.clone())
        };
        if self.config.acl == AclMode::Off || collection == SESSION_COLLECTION {
            return Ok((Decision::Allow, label));
        }
        let kind = crate::acl::kind(caller);
        let line = if kind == CallerKind::App { self.line(caller, item_id, listed).await? } else { Line::Absent };
        Ok((decide(kind, line), label))
    }

    /// The state of `caller`'s line in the item on this device. When the line
    /// is gone from the item, so is whatever this device decided about it.
    async fn line(&self, caller: &str, item_id: &str, listed: bool) -> SResult<Line> {
        let key = match self.backend.acl_trust().await? {
            AclTrust::Local => return Ok(if listed { Line::Confirmed } else { Line::Absent }),
            AclTrust::PerDevice(key) => key,
        };
        let mut guard = self.confirmed.lock().await;
        let set = guard.get_or_insert_with(|| ConfirmSet::open(self.acl_state_path.get().cloned(), key));
        Ok(match (listed, set.mark(item_id, caller)) {
            (true, Mark::Confirmed) => Line::Confirmed,
            (true, Mark::Denied) => Line::Denied,
            (true, Mark::None) => Line::Unconfirmed,
            (false, Mark::None) => Line::Absent,
            (false, Mark::Confirmed | Mark::Denied) => {
                set.set(item_id, caller, Mark::None);
                Line::Absent
            }
        })
    }

    /// Records this device's decision about `caller`'s line in the item.
    async fn remember(&self, item_id: &str, caller: &str, mark: Mark) {
        match self.backend.acl_trust().await {
            Ok(AclTrust::PerDevice(key)) => {
                let mut guard = self.confirmed.lock().await;
                guard
                    .get_or_insert_with(|| ConfirmSet::open(self.acl_state_path.get().cloned(), key))
                    .set(item_id, caller, mark);
            }
            Ok(AclTrust::Local) => {}
            Err(e) => tracing::info!("access decision not recorded: {e}"),
        }
    }

    /// "Always allow": adds `caller` to the item's ACL, which syncs, and
    /// records that this device granted it.
    async fn grant(&self, caller: &str, item_id: &str) {
        let updated = {
            let mut k = self.keyring.lock().await;
            let Some(mut item) = k.item(item_id).cloned() else { return };
            if !item.acl.iter().any(|a| a == caller) {
                item.acl.push(caller.to_owned());
            }
            k.upsert(item.clone());
            item
        };
        self.remember(item_id, caller, Mark::Confirmed).await;
        if let Err(e) = self.backend.put_item(&updated).await {
            tracing::warn!("could not save the access rule: {e}");
        }
    }

    // --- item operations -------------------------------------------------------------

    pub fn encode_secret(&self, session_path: &str, secret: &[u8], content_type: &str) -> SResult<WireSecret> {
        let s = self.session(session_path, None)?;
        let (params, value) = s.session.encrypt(secret);
        Ok((op(session_path), params, value, content_type.to_owned()))
    }

    pub fn decode_secret(&self, secret: &WireSecret, caller: Option<&str>) -> SResult<(Zeroizing<Vec<u8>>, String)> {
        let s = self.session(secret.0.as_str(), caller)?;
        let plain = s.session.decrypt(&secret.1, &secret.2).map_err(|e| SecretError::Failed(e.to_string()))?;
        let ct = if secret.3.is_empty() { "text/plain".to_owned() } else { secret.3.clone() };
        Ok((plain, ct))
    }

    /// Creates (or with `replace`, updates) an item. Returns its path.
    pub async fn create_item(
        self: &Arc<Self>,
        collection: &str,
        new: NewItem,
        caller: &str,
    ) -> SResult<OwnedObjectPath> {
        let NewItem { label, attributes, secret, content_type, replace } = new;
        let existing = {
            let k = self.keyring.lock().await;
            if k.collection(collection).is_none() {
                return Err(SecretError::NoSuchObject(format!("no collection {collection}")));
            }
            if k.collection_locked(collection) {
                return Err(SecretError::IsLocked("the collection is locked".into()));
            }
            if replace {
                // Same app attributes; derived ones (`bwss:*`) do not count (§5.1).
                let wanted = own_attributes(&attributes);
                k.search(&wanted, Some(collection))
                    .0
                    .into_iter()
                    .map(|(_, id)| id)
                    .find(|id| k.item(id).is_some_and(|i| own_attributes(&i.attributes) == wanted))
            } else {
                None
            }
        };
        let t = now();
        let item = match existing {
            Some(id) => {
                self.authorize(caller, &id, "replace").await?;
                let mut item = self
                    .keyring
                    .lock()
                    .await
                    .item(&id)
                    .cloned()
                    .ok_or_else(|| SecretError::IsLocked("locked".into()))?;
                item.label = label;
                item.secret = secret;
                item.content_type = content_type;
                item.modified = t;
                item
            }
            None => ItemData {
                id: crate::model::new_item_id(),
                collection: collection.to_owned(),
                label,
                attributes,
                secret,
                content_type,
                created: t,
                modified: t,
                // Only an identified executable gets a line: an interpreter's
                // would cover every script it runs.
                acl: if crate::acl::kind(caller) == CallerKind::App { vec![caller.to_owned()] } else { vec![] },
            },
        };
        let is_new = self.keyring.lock().await.item(&item.id).is_none();
        if collection != SESSION_COLLECTION {
            self.backend.put_item(&item).await?;
            if is_new && item.acl.iter().any(|a| a == caller) {
                self.remember(&item.id, caller, Mark::Confirmed).await;
            }
        }
        let path = op(&item_path(collection, &item.id));
        let r = (collection.to_owned(), item.id.clone());
        if !self.keyring.lock().await.upsert(item) {
            return Err(locked_during_write());
        }
        let diff = if is_new {
            Diff { created: vec![r], ..Default::default() }
        } else {
            Diff { changed: vec![r], ..Default::default() }
        };
        self.publish(diff).await;
        self.touch();
        Ok(path)
    }

    pub async fn update_item(self: &Arc<Self>, id: &str, f: impl FnOnce(&mut ItemData)) -> SResult<()> {
        let item = {
            let k = self.keyring.lock().await;
            let mut item = k.item(id).cloned().ok_or_else(|| SecretError::IsLocked("the item is locked".into()))?;
            f(&mut item);
            item.modified = now();
            item
        };
        if item.collection != SESSION_COLLECTION {
            self.backend.put_item(&item).await?;
        }
        let r = (item.collection.clone(), item.id.clone());
        if !self.keyring.lock().await.upsert(item) {
            return Err(locked_during_write());
        }
        self.publish(Diff { changed: vec![r], ..Default::default() }).await;
        self.touch();
        Ok(())
    }

    pub async fn delete_item(self: &Arc<Self>, id: &str) -> SResult<()> {
        let item = self
            .keyring
            .lock()
            .await
            .item(id)
            .cloned()
            .ok_or_else(|| SecretError::IsLocked("the item is locked".into()))?;
        if item.collection != SESSION_COLLECTION {
            self.backend.delete_item(&item).await?;
        }
        self.keyring.lock().await.remove(id);
        self.publish(Diff { deleted: vec![(item.collection.clone(), item.id.clone())], ..Default::default() }).await;
        Ok(())
    }

    pub async fn create_collection(self: &Arc<Self>, label: &str) -> SResult<OwnedObjectPath> {
        if !self.keyring.lock().await.is_unlocked() {
            return Err(SecretError::IsLocked("the keyring is locked".into()));
        }
        let c = self.backend.create_collection(label).await?;
        let id = c.id.clone();
        self.keyring.lock().await.add_collection(c);
        self.publish(Diff { collections_created: vec![id.clone()], ..Default::default() }).await;
        Ok(op(&collection_path(&id)))
    }

    /// Deletes a collection and the items in `authorized`, the ones the
    /// caller was allowed to delete.
    pub async fn delete_collection(self: &Arc<Self>, id: &str, authorized: &[String]) -> SResult<()> {
        if id == LOGIN_COLLECTION || id == SESSION_COLLECTION {
            return Err(SecretError::NotSupported("built-in collections cannot be deleted".into()));
        }
        if !self.keyring.lock().await.is_unlocked() {
            return Err(SecretError::IsLocked("the keyring is locked".into()));
        }
        self.backend.delete_collection(id, authorized).await?;
        let gone = self.keyring.lock().await.remove_collection(id);
        self.publish(Diff {
            deleted: gone.into_iter().map(|i| (id.to_owned(), i)).collect(),
            collections_deleted: vec![id.to_owned()],
            ..Default::default()
        })
        .await;
        Ok(())
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn parse_path_unescapes_ids() {
        assert_eq!(parse_path(&item_path("work/keys", "a b")), Some(("work/keys".into(), Some("a b".into()))));
        assert_eq!(parse_path(&format!("{SERVICE_PATH}/collection/_zz")), None);
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn eviction_policy_takes_the_oldest_only_at_the_cap() {
        assert_eq!(oldest_to_evict([5, 3, 9], 4), None);
        assert_eq!(oldest_to_evict([5, 3, 9], 3), Some(3));
        assert_eq!(oldest_to_evict([], 1), None);
        assert_eq!(oldest_to_evict([7], 1), Some(7));
    }

    #[test]
    fn prompt_slot_dismisses_the_oldest_unstarted_prompt() {
        assert_eq!(prompt_slot([(1, false), (2, false)], 3), PromptSlot::Free);
        // The oldest is running, so the next oldest goes.
        assert_eq!(prompt_slot([(1, true), (2, false), (3, false)], 3), PromptSlot::Evict(2));
        assert_eq!(prompt_slot([(4, false), (2, false), (3, true)], 3), PromptSlot::Evict(2));
        assert_eq!(prompt_slot([(1, true), (2, true)], 2), PromptSlot::Full);
    }

    #[test]
    fn only_registered_idle_prompts_can_be_dismissed() {
        let entry = |started, registered| PromptEntry {
            seq: 1,
            path: String::new(),
            owner: String::new(),
            started,
            registered,
        };
        assert!(!entry(false, true).pinned());
        assert!(entry(true, true).pinned());
        assert!(entry(false, false).pinned(), "a placeholder must never be a victim");
        // A pinned oldest prompt is skipped in favour of the next one.
        assert_eq!(prompt_slot([(1, entry(false, false).pinned()), (2, false)], 2), PromptSlot::Evict(2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_remote_attempt_waits_for_the_interactive_unlock_gate() {
        let (d, _backend) = gated_daemon(None).await;
        let gate = d.unlock_gate.lock().await;
        let attempt = {
            let d = d.clone();
            tokio::spawn(async move { d.unlock_with_password_throttled("pw").await })
        };
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!attempt.is_finished(), "the attempt must not run beside an interactive unlock");
        drop(gate);
        attempt.await.unwrap().unwrap();
    }

    #[test]
    fn fattest_owner_is_the_one_with_most_sessions() {
        assert_eq!(fattest_owner([":1.2", ":1.1", ":1.2", ":1.3"]), Some(":1.2"));
        assert_eq!(fattest_owner([":1.2", ":1.1"]), Some(":1.1"));
        assert_eq!(fattest_owner([]), None);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_password_attempts_take_turns_and_never_hold_the_unlock_gate() {
        let (d, _backend) = gated_daemon(None).await;
        let start = tokio::time::Instant::now();
        let attempts: Vec<_> = (0..2)
            .map(|_| {
                let d = d.clone();
                tokio::spawn(async move { d.unlock_with_password_throttled("wrong").await.is_err() })
            })
            .collect();
        // While the penalty runs, the interactive unlock path is not blocked.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(d.unlock_gate.try_lock().is_ok(), "remote attempts must not hold the interactive gate");
        for a in attempts {
            assert!(a.await.unwrap());
        }
        assert!(start.elapsed() >= 2 * FAILED_UNLOCK_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_interactive_unlocks_take_turns_and_never_hold_the_unlock_gate() {
        // A prompter that cannot start: every interactive unlock fails at once.
        let prompter = Prompter::new("/nonexistent/bwss-test-pinentry", Duration::from_secs(1));
        let d = Daemon::new(Keyring::new(None), Arc::new(MemoryBackend::new("pw")), prompter, Config::default());
        let start = tokio::time::Instant::now();
        let attempts: Vec<_> = (0..2)
            .map(|_| {
                let d = d.clone();
                tokio::spawn(async move { d.unlock_interactive_throttled().await })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(d.unlock_gate.try_lock().is_ok(), "the penalty must not hold the interactive gate");
        for a in attempts {
            assert!(!a.await.unwrap());
        }
        assert!(start.elapsed() >= 2 * FAILED_UNLOCK_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn interactive_unlock_of_an_unlocked_keyring_succeeds_without_delay() {
        let (d, _backend) = gated_daemon(None).await;
        let start = tokio::time::Instant::now();
        assert!(d.unlock_interactive_throttled().await);
        assert!(start.elapsed() < FAILED_UNLOCK_DELAY);
    }

    use crate::backend::memory::MemoryBackend;
    use crate::model::{CollectionData, Snapshot};
    use tokio::sync::Notify;

    /// A memory backend whose `put_item` stops until the test lets it go.
    struct GatedBackend {
        inner: MemoryBackend,
        entered: Notify,
        release: Notify,
    }

    #[async_trait::async_trait]
    impl Backend for GatedBackend {
        async fn unlock(&self, password: &str) -> Result<Snapshot, BackendError> {
            self.inner.unlock(password).await
        }
        async fn lock(&self) {
            self.inner.lock().await;
        }
        async fn refresh(&self) -> Result<Option<Snapshot>, BackendError> {
            self.inner.refresh().await
        }
        async fn create_collection(&self, label: &str) -> Result<CollectionData, BackendError> {
            self.inner.create_collection(label).await
        }
        async fn delete_collection(&self, id: &str, items: &[String]) -> Result<(), BackendError> {
            self.inner.delete_collection(id, items).await
        }
        async fn put_item(&self, item: &ItemData) -> Result<(), BackendError> {
            // Stored, but the answer is held back until the test says so.
            self.inner.put_item(item).await?;
            self.entered.notify_one();
            self.release.notified().await;
            Ok(())
        }
        async fn delete_item(&self, item: &ItemData) -> Result<(), BackendError> {
            self.inner.delete_item(item).await
        }
        async fn acl_trust(&self) -> Result<AclTrust, BackendError> {
            self.inner.acl_trust().await
        }
        async fn describe(&self) -> String {
            self.inner.describe().await
        }
    }

    async fn gated_daemon(seed: Option<ItemData>) -> (Arc<Daemon>, Arc<GatedBackend>) {
        let backend =
            Arc::new(GatedBackend { inner: MemoryBackend::new("pw"), entered: Notify::new(), release: Notify::new() });
        if let Some(item) = seed {
            backend.inner.unlock("pw").await.unwrap();
            backend.inner.put_item(&item).await.unwrap();
        }
        let prompter = Prompter::new("false", Duration::from_secs(1));
        let d = Daemon::new(Keyring::new(None), backend.clone(), prompter, Config::default());
        d.unlock_with_password("pw").await.unwrap();
        (d, backend)
    }

    fn stored_item(id: &str) -> ItemData {
        ItemData {
            id: id.into(),
            collection: LOGIN_COLLECTION.into(),
            label: "l".into(),
            attributes: Attributes::from([("k".to_owned(), "v".to_owned())]),
            secret: Zeroizing::new(b"s".to_vec()),
            content_type: "text/plain".into(),
            created: 1,
            modified: 1,
            acl: vec![],
        }
    }

    #[tokio::test]
    async fn lock_during_create_keeps_nothing_in_memory() {
        let (d, backend) = gated_daemon(None).await;
        let new = NewItem {
            label: "l".into(),
            attributes: Attributes::from([("k".to_owned(), "v".to_owned())]),
            secret: Zeroizing::new(b"s".to_vec()),
            content_type: "text/plain".into(),
            replace: false,
        };
        let task = tokio::spawn({
            let d = d.clone();
            async move { d.create_item(LOGIN_COLLECTION, new, "/usr/bin/x").await }
        });
        backend.entered.notified().await;
        d.lock().await;
        backend.release.notify_one();
        assert!(matches!(task.await.unwrap(), Err(SecretError::IsLocked(_))));
        let k = d.keyring.lock().await;
        assert!(k.item_refs().is_empty());
        assert!(!k.is_unlocked());
        drop(k);
        // The backend stored it, so the next unlock shows it.
        d.unlock_with_password("pw").await.unwrap();
        assert_eq!(d.keyring.lock().await.item_refs().len(), 1);
    }

    #[tokio::test]
    async fn lock_during_update_drops_the_item() {
        let (d, backend) = gated_daemon(Some(stored_item("x"))).await;
        let task = tokio::spawn({
            let d = d.clone();
            async move { d.update_item("x", |i| i.label = "new".into()).await }
        });
        backend.entered.notified().await;
        d.lock().await;
        backend.release.notify_one();
        assert!(matches!(task.await.unwrap(), Err(SecretError::IsLocked(_))));
        assert!(d.keyring.lock().await.item("x").is_none());
        d.unlock_with_password("pw").await.unwrap();
        assert_eq!(d.keyring.lock().await.item("x").unwrap().label, "new");
    }

    #[tokio::test]
    async fn replace_ignores_derived_attributes() {
        let backend = Arc::new(MemoryBackend::new("pw"));
        backend.unlock("pw").await.unwrap();
        let stored = ItemData {
            id: "x".into(),
            collection: LOGIN_COLLECTION.into(),
            label: "GitHub".into(),
            attributes: Attributes::from([
                ("service".to_owned(), "git".to_owned()),
                ("bwss:id".to_owned(), "x".to_owned()),
                ("bwss:name".to_owned(), "GitHub".to_owned()),
            ]),
            secret: Zeroizing::new(b"old".to_vec()),
            content_type: "text/plain".into(),
            created: 1,
            modified: 1,
            acl: vec!["/usr/bin/git".into()],
        };
        backend.put_item(&stored).await.unwrap();
        let prompter = Prompter::new("false", Duration::from_secs(1));
        let d = Daemon::new(Keyring::new(None), backend, prompter, Config::default());
        d.unlock_with_password("pw").await.unwrap();

        let new = NewItem {
            label: "GitHub token".into(),
            attributes: Attributes::from([("service".to_owned(), "git".to_owned())]),
            secret: Zeroizing::new(b"new".to_vec()),
            content_type: "text/plain".into(),
            replace: true,
        };
        let path = d.create_item(LOGIN_COLLECTION, new, "/usr/bin/git").await.unwrap();
        assert_eq!(path.as_str(), item_path(LOGIN_COLLECTION, "x"));
        let k = d.keyring.lock().await;
        assert_eq!(k.item_refs(), [(LOGIN_COLLECTION.to_owned(), "x".to_owned())]);
        let item = k.item("x").unwrap();
        assert_eq!(&*item.secret, b"new");
        assert_eq!(own_attributes(&item.attributes), Attributes::from([("service".to_owned(), "git".to_owned())]));
    }

    #[test]
    fn decision_table() {
        use CallerKind::{App, Interpreter, Unknown};
        for line in [Line::Absent, Line::Confirmed, Line::Denied, Line::Unconfirmed] {
            assert_eq!(decide(Unknown, line), Decision::Ask { always: false }, "{line:?}");
            assert_eq!(decide(Interpreter, line), Decision::Ask { always: false }, "{line:?}");
        }
        assert_eq!(decide(App, Line::Absent), Decision::Ask { always: true });
        assert_eq!(decide(App, Line::Confirmed), Decision::Allow);
        assert_eq!(decide(App, Line::Denied), Decision::Deny);
        assert_eq!(decide(App, Line::Unconfirmed), Decision::ConfirmLine);
    }

    #[test]
    fn prompts_say_why_always_is_missing() {
        assert!(ask_text("/usr/bin/git", "read", "l", CallerKind::App).ends_with("\"l\""));
        assert!(ask_text("/usr/bin/python3", "read", "l", CallerKind::Interpreter).contains("runs scripts"));
        assert!(ask_text(crate::acl::UNKNOWN, "read", "l", CallerKind::Unknown).contains("cannot tell which"));
        assert!(
            confirm_line_text("/usr/bin/git", "read", "l")
                .starts_with("Allow /usr/bin/git, granted on another device?")
        );
    }

    /// A memory backend whose ACL lines may come from elsewhere, like Bitwarden's.
    struct SyncedBackend {
        inner: MemoryBackend,
        key: crate::bw::crypto::SymmetricKey,
    }

    #[async_trait::async_trait]
    impl Backend for SyncedBackend {
        async fn unlock(&self, password: &str) -> Result<Snapshot, BackendError> {
            self.inner.unlock(password).await
        }
        async fn lock(&self) {
            self.inner.lock().await;
        }
        async fn refresh(&self) -> Result<Option<Snapshot>, BackendError> {
            self.inner.refresh().await
        }
        async fn create_collection(&self, label: &str) -> Result<CollectionData, BackendError> {
            self.inner.create_collection(label).await
        }
        async fn delete_collection(&self, id: &str, items: &[String]) -> Result<(), BackendError> {
            self.inner.delete_collection(id, items).await
        }
        async fn put_item(&self, item: &ItemData) -> Result<(), BackendError> {
            self.inner.put_item(item).await
        }
        async fn delete_item(&self, item: &ItemData) -> Result<(), BackendError> {
            self.inner.delete_item(item).await
        }
        async fn acl_trust(&self) -> Result<AclTrust, BackendError> {
            self.inner.acl_trust().await?;
            Ok(AclTrust::PerDevice(self.key.clone()))
        }
        async fn describe(&self) -> String {
            self.inner.describe().await
        }
    }

    /// A pinentry that answers every CONFIRM with `confirm` ("OK" or a
    /// cancel) and logs the commands it gets.
    struct ScriptedPinentry {
        dir: tempfile::TempDir,
    }

    impl ScriptedPinentry {
        fn new(allow: bool) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("log");
            let answer = if allow { "OK" } else { "ERR 83886179 Operation cancelled" };
            let script = format!(
                "#!/bin/sh\necho OK\nwhile IFS= read -r l; do\n  printf '%s\\n' \"$l\" >> '{}'\n  case \"$l\" in\n    CONFIRM*) echo '{answer}' ;;\n    BYE*) echo OK; exit 0 ;;\n    *) echo OK ;;\n  esac\ndone\n",
                log.display()
            );
            let path = dir.path().join("pinentry");
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            ScriptedPinentry { dir }
        }

        fn prompter(&self) -> Prompter {
            Prompter::new(self.dir.path().join("pinentry").to_string_lossy(), Duration::from_secs(10))
        }

        fn log(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.path().join("log"))
                .map(|t| t.lines().map(str::to_owned).collect())
                .unwrap_or_default()
        }

        fn confirms(&self) -> usize {
            self.log().iter().filter(|l| l.starts_with("CONFIRM")).count()
        }
    }

    const GIT: &str = "/usr/bin/git";

    /// A daemon over a synced backend holding `stored_item("x")` with `acl`,
    /// keeping its confirmations in `state`.
    async fn synced_daemon(acl: &[&str], pinentry: &ScriptedPinentry, state: &std::path::Path) -> Arc<Daemon> {
        let backend =
            SyncedBackend { inner: MemoryBackend::new("pw"), key: crate::bw::crypto::SymmetricKey::generate() };
        backend.inner.unlock("pw").await.unwrap();
        let mut item = stored_item("x");
        item.acl = acl.iter().map(|s| (*s).to_owned()).collect();
        backend.inner.put_item(&item).await.unwrap();
        let d = Daemon::new(Keyring::new(None), Arc::new(backend), pinentry.prompter(), Config::default());
        d.set_acl_state_path(state.join("acl-confirmed"));
        d.unlock_with_password("pw").await.unwrap();
        d
    }

    #[tokio::test]
    async fn a_synced_line_is_confirmed_once_per_device() {
        let state = tempfile::tempdir().unwrap();
        let pin = ScriptedPinentry::new(true);
        let d = synced_daemon(&[GIT], &pin, state.path()).await;
        d.authorize(GIT, "x", "read").await.unwrap();
        assert_eq!(pin.confirms(), 1, "exactly one question, with no 'Always allow' step");
        assert!(pin.log().iter().any(|l| l.contains("granted on another device")), "{:?}", pin.log());
        assert!(!pin.log().iter().any(|l| l.contains("Always allow")));
        d.authorize(GIT, "x", "read").await.unwrap();
        assert_eq!(pin.confirms(), 1, "confirmed lines are not asked about again");
        assert!(state.path().join("acl-confirmed").exists());
        // Locking drops the set with its key; it comes back from the file.
        d.lock().await;
        d.unlock_with_password("pw").await.unwrap();
        d.authorize(GIT, "x", "read").await.unwrap();
        assert_eq!(pin.confirms(), 1);
    }

    #[tokio::test]
    async fn a_denied_synced_line_stays_denied_without_asking_until_it_changes() {
        let state = tempfile::tempdir().unwrap();
        let pin = ScriptedPinentry::new(false);
        let d = synced_daemon(&[GIT], &pin, state.path()).await;
        assert!(matches!(d.authorize(GIT, "x", "read").await, Err(SecretError::AccessDenied(_))));
        assert_eq!(pin.confirms(), 1);
        assert!(matches!(d.authorize(GIT, "x", "read").await, Err(SecretError::AccessDenied(_))));
        assert_eq!(pin.confirms(), 1, "a remembered denial asks nothing");

        // The line goes away: git is an ordinary unlisted caller again.
        let mut item = d.keyring.lock().await.item("x").cloned().unwrap();
        item.acl.clear();
        d.keyring.lock().await.upsert(item.clone());
        assert!(d.authorize(GIT, "x", "read").await.is_err());
        assert_eq!(pin.confirms(), 2);
        // When it comes back, it is a new line to confirm.
        item.acl.push(GIT.into());
        d.keyring.lock().await.upsert(item);
        assert!(d.authorize(GIT, "x", "read").await.is_err());
        assert_eq!(pin.confirms(), 3);
        assert!(pin.log().last().is_some_and(|l| l.starts_with("BYE")));
        assert!(pin.log().iter().filter(|l| l.contains("granted on another device")).count() == 2);
    }

    #[tokio::test]
    async fn interpreters_and_unknown_callers_are_asked_every_time() {
        let state = tempfile::tempdir().unwrap();
        let pin = ScriptedPinentry::new(true);
        let python = "/usr/bin/python3.13";
        let d = synced_daemon(&[python, crate::acl::UNKNOWN], &pin, state.path()).await;
        for caller in [python, crate::acl::UNKNOWN] {
            let before = pin.confirms();
            d.authorize(caller, "x", "read").await.unwrap();
            d.authorize(caller, "x", "read").await.unwrap();
            assert_eq!(pin.confirms(), before + 2, "{caller}: a line in the item never counts");
        }
        assert!(!pin.log().iter().any(|l| l.contains("Always allow")), "{:?}", pin.log());
        assert!(pin.log().iter().any(|l| l.contains("runs scripts")));
        assert!(pin.log().iter().any(|l| l.contains("cannot tell which application")));
        let acl = d.keyring.lock().await.item("x").unwrap().acl.clone();
        assert_eq!(acl, [python, crate::acl::UNKNOWN], "nothing was added");
    }

    #[tokio::test]
    async fn always_allow_lists_and_confirms_the_app_here() {
        let state = tempfile::tempdir().unwrap();
        let pin = ScriptedPinentry::new(true);
        let d = synced_daemon(&[], &pin, state.path()).await;
        d.authorize(GIT, "x", "read").await.unwrap();
        assert_eq!(pin.confirms(), 2, "allow, then remember");
        assert!(pin.log().iter().any(|l| l == "SETOK Always allow"));
        assert_eq!(d.keyring.lock().await.item("x").unwrap().acl, [GIT]);
        d.authorize(GIT, "x", "read").await.unwrap();
        assert_eq!(pin.confirms(), 2, "granted on this device: no question");
    }

    #[tokio::test]
    async fn the_creator_is_confirmed_unless_it_is_an_interpreter() {
        let state = tempfile::tempdir().unwrap();
        let pin = ScriptedPinentry::new(false);
        let d = synced_daemon(&[], &pin, state.path()).await;
        let new = |label: &str| NewItem {
            label: label.into(),
            attributes: Attributes::from([("app".to_owned(), label.to_owned())]),
            secret: Zeroizing::new(b"s".to_vec()),
            content_type: "text/plain".into(),
            replace: false,
        };
        let git_path = d.create_item(LOGIN_COLLECTION, new("git"), GIT).await.unwrap();
        let (_, git_id) = parse_path(git_path.as_str()).unwrap();
        d.authorize(GIT, &git_id.unwrap(), "read").await.unwrap();
        assert_eq!(pin.confirms(), 0, "the creator needs no question");

        let py_path = d.create_item(LOGIN_COLLECTION, new("py"), "/usr/bin/python3").await.unwrap();
        let py_id = parse_path(py_path.as_str()).unwrap().1.unwrap();
        assert!(d.keyring.lock().await.item(&py_id).unwrap().acl.is_empty());
        assert!(d.authorize("/usr/bin/python3", &py_id, "read").await.is_err());
        assert_eq!(pin.confirms(), 1);
    }

    #[tokio::test]
    async fn without_acl_checks_nothing_is_asked() {
        let backend = Arc::new(MemoryBackend::new("pw"));
        let pin = ScriptedPinentry::new(false);
        let config = Config { acl: AclMode::Off, ..Config::default() };
        let d = Daemon::new(Keyring::new(None), backend.clone(), pin.prompter(), config);
        d.unlock_with_password("pw").await.unwrap();
        backend.put_item(&stored_item("x")).await.unwrap();
        d.keyring.lock().await.upsert(stored_item("x"));
        d.authorize(crate::acl::UNKNOWN, "x", "read").await.unwrap();
        assert_eq!(pin.confirms(), 0);
    }

    #[test]
    fn conflict_maps_to_a_retry_message() {
        match SecretError::from(BackendError::Conflict("the secret was changed elsewhere".into())) {
            SecretError::Failed(m) => assert_eq!(m, "the secret was changed elsewhere; try again"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(SecretError::from(BackendError::Rejected("no".into())), SecretError::Failed(_)));
    }
}
