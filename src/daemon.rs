//! Shared daemon state and the operations behind the D-Bus objects.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use zbus::{Connection, OwnedObjectPath, object_server::SignalEmitter};
use zeroize::Zeroizing;

use crate::backend::{Backend, BackendError};
use crate::config::{AclMode, Config};
use crate::dbus::{CollectionObj, ItemObj, ServiceObj};
use crate::keyring::{Diff, Keyring};
use crate::model::{Attributes, ItemData, LOGIN_COLLECTION, SESSION_COLLECTION, VAULT_COLLECTION, now, path_segment};
use crate::prompter::{Confirm, Prompter};
use crate::session::Session;

pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
pub const DEFAULT_ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";

pub fn collection_path(id: &str) -> String {
    format!("{SERVICE_PATH}/collection/{id}")
}

pub fn item_path(collection: &str, id: &str) -> String {
    format!("{SERVICE_PATH}/collection/{collection}/{id}")
}

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
    let c = parts.next().filter(|s| !s.is_empty())?.to_owned();
    let i = parts.next().map(str::to_owned);
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
            other => SecretError::Failed(other.to_string()),
        }
    }
}

pub type SResult<T> = Result<T, SecretError>;

/// Nothing can be added to the `vault` collection: it only shows the user's
/// Bitwarden vault.
pub fn ensure_writable(collection: &str) -> SResult<()> {
    if collection == VAULT_COLLECTION {
        return Err(SecretError::NotSupported("the vault collection is read-only".into()));
    }
    Ok(())
}

/// Vault items belong to the user's Bitwarden vault, not to the keyring, in
/// whatever collection they show up: apps may read them but never change them.
fn ensure_item_writable(item: &ItemData) -> SResult<()> {
    if item.read_only {
        return Err(SecretError::NotSupported(format!("\"{}\" is a read-only vault item", item.label)));
    }
    Ok(())
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

pub struct OpenSession {
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
    registered: Mutex<BTreeSet<String>>,
    counter: AtomicU64,
    last_activity: std::sync::Mutex<Instant>,
    /// Only one interactive unlock (and one access prompt) at a time.
    unlock_gate: Mutex<()>,
    confirm_gate: Mutex<()>,
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
            registered: Mutex::new(BTreeSet::new()),
            counter: AtomicU64::new(1),
            last_activity: std::sync::Mutex::new(Instant::now()),
            unlock_gate: Mutex::new(()),
            confirm_gate: Mutex::new(()),
        })
    }

    pub fn set_connection(&self, conn: Connection) {
        let _ = self.conn.set(conn);
    }

    pub fn conn(&self) -> &Connection {
        self.conn.get().expect("connection set at startup")
    }

    pub fn next_id(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }

    pub fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    pub fn idle_for(&self) -> Duration {
        self.last_activity.lock().unwrap().elapsed()
    }

    pub fn session(&self, path: &str, caller: Option<&str>) -> SResult<Arc<OpenSession>> {
        let sessions = self.sessions.lock().unwrap();
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
        if let Err(e) = self.sync_objects().await {
            tracing::warn!("could not update D-Bus objects: {e}");
        }
        let conn = self.conn();
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
        let (label, acl, collection) = {
            let k = self.keyring.lock().await;
            let item = k.item(item_id).ok_or_else(|| SecretError::IsLocked("the item is locked".into()))?;
            if action != "read" {
                ensure_item_writable(item)?;
            }
            (item.label.clone(), item.acl.clone(), item.collection.clone())
        };
        if self.config.acl == AclMode::Off || collection == SESSION_COLLECTION || acl.iter().any(|a| a == caller) {
            return Ok(());
        }
        let _gate = self.confirm_gate.lock().await;
        let answer = self
            .prompter
            .confirm(&format!("{caller}\n\nwants to {action} the keyring item\n\n\"{label}\""))
            .await
            .unwrap_or(Confirm::Deny);
        match answer {
            Confirm::Once => Ok(()),
            Confirm::Always => {
                let updated = {
                    let mut k = self.keyring.lock().await;
                    let Some(item) = k.item(item_id).cloned() else { return Ok(()) };
                    let mut item = item;
                    if !item.acl.iter().any(|a| a == caller) {
                        item.acl.push(caller.to_owned());
                    }
                    k.upsert(item.clone());
                    item
                };
                if let Err(e) = self.backend.put_item(&updated).await {
                    tracing::warn!("could not save the access rule: {e}");
                }
                Ok(())
            }
            Confirm::Deny => Err(SecretError::AccessDenied(format!("{caller} was denied access to \"{label}\""))),
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
            ensure_writable(collection)?;
            if k.collection_locked(collection) {
                return Err(SecretError::IsLocked("the collection is locked".into()));
            }
            if replace {
                k.search(&attributes, Some(collection))
                    .0
                    .into_iter()
                    .map(|(_, id)| id)
                    // A read-only vault item is never replaced: the new item is stored beside it.
                    .find(|id| k.item(id).is_some_and(|i| i.attributes == attributes && !i.read_only))
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
                acl: if caller == crate::acl::UNKNOWN { vec![] } else { vec![caller.to_owned()] },
                read_only: false,
            },
        };
        let is_new = self.keyring.lock().await.item(&item.id).is_none();
        if collection != SESSION_COLLECTION {
            self.backend.put_item(&item).await?;
        }
        let path = op(&item_path(collection, &item.id));
        let r = (collection.to_owned(), item.id.clone());
        self.keyring.lock().await.upsert(item);
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
            ensure_item_writable(&item)?;
            f(&mut item);
            item.modified = now();
            item
        };
        if item.collection != SESSION_COLLECTION {
            self.backend.put_item(&item).await?;
        }
        let r = (item.collection.clone(), item.id.clone());
        self.keyring.lock().await.upsert(item);
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
        ensure_item_writable(&item)?;
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
        let id = path_segment(&c.id);
        self.keyring.lock().await.add_collection(c);
        self.publish(Diff { collections_created: vec![id.clone()], ..Default::default() }).await;
        Ok(op(&collection_path(&id)))
    }

    pub async fn delete_collection(self: &Arc<Self>, id: &str) -> SResult<()> {
        if id == LOGIN_COLLECTION || id == SESSION_COLLECTION || id == VAULT_COLLECTION {
            return Err(SecretError::NotSupported("built-in collections cannot be deleted".into()));
        }
        if !self.keyring.lock().await.is_unlocked() {
            return Err(SecretError::IsLocked("the keyring is locked".into()));
        }
        self.backend.delete_collection(id).await?;
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
