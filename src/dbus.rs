//! The org.freedesktop.Secret.* interfaces. Thin wrappers over `Daemon`.

use std::collections::HashMap;
use std::sync::Arc;

use zbus::{OwnedObjectPath, OwnedVariant, Variant, interface, message::Header, object_server::SignalEmitter};
use zeroize::Zeroizing;

use crate::daemon::{
    Daemon, NewItem, OpenSession, PROMPTS_PER_OWNER, PromptEntry, PromptSlot, SERVICE_PATH, SResult, SecretError,
    WireSecret, collection_path, emitter, item_path, no_prompt, op, parse_path, prompt_slot,
};
use crate::model::{Attributes, LOGIN_COLLECTION, SESSION_COLLECTION};
use crate::session::Session;
use crate::sync::lock;

const PROP_ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
const PROP_ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";
const PROP_COLLECTION_LABEL: &str = "org.freedesktop.Secret.Collection.Label";

fn sender(header: &Header<'_>) -> Option<String> {
    header.sender().map(|s| s.to_string())
}

fn prop_string(props: &HashMap<String, OwnedVariant>, key: &str) -> String {
    props.get(key).and_then(|v| String::try_from(v.try_clone().ok()?).ok()).unwrap_or_default()
}

fn prop_attributes(props: &HashMap<String, OwnedVariant>) -> Attributes {
    props
        .get(PROP_ITEM_ATTRIBUTES)
        .and_then(|v| HashMap::<String, String>::try_from(v.try_clone().ok()?).ok())
        .map(|m| m.into_iter().collect())
        .unwrap_or_default()
}

/// A secret as one struct `(oayays)`. zbus spreads a returned struct or tuple
/// over several out-arguments, so methods return it wrapped in a 1-tuple.
#[derive(serde::Serialize, zbus::wire::Type)]
pub struct SecretStruct {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

impl From<WireSecret> for SecretStruct {
    fn from((session, parameters, value, content_type): WireSecret) -> Self {
        SecretStruct { session, parameters, value, content_type }
    }
}

#[expect(clippy::expect_used, reason = "a string always converts to an owned variant")]
fn empty_variant() -> OwnedVariant {
    OwnedVariant::try_from(Variant::from("")).expect("string variant")
}

// --- Service --------------------------------------------------------------------

pub struct ServiceObj {
    pub daemon: Arc<Daemon>,
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl ServiceObj {
    async fn open_session(
        &self,
        algorithm: &str,
        input: OwnedVariant,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(OwnedVariant, OwnedObjectPath), SecretError> {
        let bytes: Vec<u8> = Vec::<u8>::try_from(input.try_clone().map_err(SecretError::ZBus)?).unwrap_or_default();
        let owner = sender(&header).unwrap_or_default();
        let (output, path) = open_tracked_session(&self.daemon, algorithm, &bytes, owner).await?;
        let out = if output.is_empty() {
            empty_variant()
        } else {
            OwnedVariant::try_from(Variant::from(output)).map_err(SecretError::ZBus)?
        };
        Ok((out, op(&path)))
    }

    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedVariant>,
        alias: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        if alias == "default" {
            return Ok((op(&collection_path(LOGIN_COLLECTION)), no_prompt()));
        }
        let label = prop_string(&properties, PROP_COLLECTION_LABEL);
        if !self.daemon.keyring.lock().await.is_unlocked() {
            let prompt =
                PromptObj::register(&self.daemon, sender(&header), PromptAction::CreateCollection { label }).await?;
            return Ok((no_prompt(), prompt));
        }
        Ok((self.daemon.create_collection(&label).await?, no_prompt()))
    }

    async fn search_items(&self, attributes: HashMap<String, String>) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let query: Attributes = attributes.into_iter().collect();
        let (unlocked, locked) = self.daemon.keyring.lock().await.search(&query, None);
        let paths = |v: Vec<(String, String)>| v.into_iter().map(|(c, i)| op(&item_path(&c, &i))).collect();
        (paths(unlocked), paths(locked))
    }

    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), SecretError> {
        let k = self.daemon.keyring.lock().await;
        if k.is_unlocked() {
            return Ok((objects, no_prompt()));
        }
        let (already, pending): (Vec<_>, Vec<_>) = objects
            .into_iter()
            .partition(|o| matches!(parse_path(o.as_str()), Some((c, _)) if c == SESSION_COLLECTION));
        drop(k);
        if pending.is_empty() {
            return Ok((already, no_prompt()));
        }
        let prompt =
            PromptObj::register(&self.daemon, sender(&header), PromptAction::Unlock { objects: pending }).await?;
        Ok((already, prompt))
    }

    async fn lock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        let lockable: Vec<OwnedObjectPath> = objects
            .into_iter()
            .filter(|o| !matches!(parse_path(o.as_str()), Some((c, _)) if c == SESSION_COLLECTION))
            .collect();
        if !lockable.is_empty() {
            self.daemon.lock().await;
        }
        (lockable, no_prompt())
    }

    async fn lock_service(&self) {
        self.daemon.lock().await;
    }

    async fn change_lock(&self, _collection: OwnedObjectPath) -> Result<OwnedObjectPath, SecretError> {
        Err(SecretError::NotSupported(
            "the keyring password is the Bitwarden master password; change it in Bitwarden".into(),
        ))
    }

    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<HashMap<OwnedObjectPath, WireSecret>, SecretError> {
        self.daemon.session(session.as_str(), sender(&header).as_deref())?;
        let caller = self.daemon.caller(&header).await;
        let mut out = HashMap::new();
        for path in items {
            let Some((_, Some(id))) = parse_path(path.as_str()) else { continue };
            if self.daemon.keyring.lock().await.item_locked(&id) {
                continue;
            }
            if self.daemon.authorize(&caller, &id, "read").await.is_err() {
                continue;
            }
            let Some((secret, ct)) =
                self.daemon.keyring.lock().await.item(&id).map(|i| (i.secret.clone(), i.content_type.clone()))
            else {
                continue;
            };
            out.insert(path, self.daemon.encode_secret(session.as_str(), &secret, &ct)?);
        }
        self.daemon.touch();
        Ok(out)
    }

    async fn read_alias(&self, name: &str) -> OwnedObjectPath {
        let k = self.daemon.keyring.lock().await;
        match name {
            "default" | "login" => op(&collection_path(LOGIN_COLLECTION)),
            "session" => op(&collection_path(SESSION_COLLECTION)),
            other if k.collection(other).is_some() => op(&collection_path(other)),
            _ => no_prompt(),
        }
    }

    async fn set_alias(&self, name: &str, collection: OwnedObjectPath) -> Result<(), SecretError> {
        // Only the built-in mapping exists; accept no-op requests so clients
        // that re-assert "default" keep working.
        match (name, parse_path(collection.as_str())) {
            ("default", Some((c, None))) if c == LOGIN_COLLECTION => Ok(()),
            _ => Err(SecretError::NotSupported("aliases other than default → login are not supported".into())),
        }
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        self.daemon.keyring.lock().await.collections().map(|c| op(&collection_path(&c.id))).collect()
    }

    #[zbus(signal)]
    pub async fn collection_created(emitter: &SignalEmitter<'_>, collection: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn collection_deleted(emitter: &SignalEmitter<'_>, collection: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn collection_changed(emitter: &SignalEmitter<'_>, collection: OwnedObjectPath) -> zbus::Result<()>;
}

/// Opens a session for the bus name `owner` and puts its object on the bus.
/// Returns what the client needs to complete the key exchange (empty for
/// `plain`) and the session's path.
async fn open_tracked_session(
    daemon: &Arc<Daemon>,
    algorithm: &str,
    input: &[u8],
    owner: String,
) -> SResult<(Vec<u8>, String)> {
    let (session, output) = Session::open(algorithm, input).map_err(|e| SecretError::NotSupported(e.to_string()))?;
    let seq = daemon.next_id();
    let path = format!("{SERVICE_PATH}/session/s{seq}");
    let open = Arc::new(OpenSession { seq, owner, session });
    let (mut dropped, admitted) = daemon.admit_session(open.clone(), &path, false);
    if !admitted {
        // Full: free what departed clients left behind before pushing
        // out a live one.
        daemon.reap_departed().await;
        dropped.extend(daemon.admit_session(open, &path, true).0);
    }
    let server = daemon.conn().object_server();
    for p in dropped {
        let _ = server.remove::<SessionObj, _>(p.as_str()).await;
    }
    #[cfg(test)]
    daemon.before_adding().await;
    // Adding fails only for an invalid path; it is cleaned up like a session
    // that was evicted or dropped with its client while the object was being
    // added, which is no longer tracked and so must not stay on the bus.
    let added = server.at(path.as_str(), SessionObj { daemon: daemon.clone(), path: path.clone() }).await;
    if added.is_err() || !lock(&daemon.sessions).contains_key(&path) {
        lock(&daemon.sessions).remove(&path);
        let _ = server.remove::<SessionObj, _>(path.as_str()).await;
        let closed = SecretError::Failed("the session was closed while opening".into());
        return Err(added.err().map_or(closed, SecretError::ZBus));
    }
    Ok((output, path))
}

// --- Collection -----------------------------------------------------------------

pub struct CollectionObj {
    pub daemon: Arc<Daemon>,
    pub id: String,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionObj {
    async fn delete(&self, #[zbus(header)] header: Header<'_>) -> Result<OwnedObjectPath, SecretError> {
        // Deleting a collection deletes its items: the caller needs the same
        // permission it would need to delete each one of them.
        let caller = self.daemon.caller(&header).await;
        let ids = self.daemon.keyring.lock().await.items_in(&self.id);
        for id in &ids {
            self.daemon.authorize(&caller, id, "delete").await?;
        }
        // Only these may go: an item that joins meanwhile was not authorized.
        self.daemon.delete_collection(&self.id, &ids).await?;
        Ok(no_prompt())
    }

    async fn search_items(&self, attributes: HashMap<String, String>) -> Vec<OwnedObjectPath> {
        let query: Attributes = attributes.into_iter().collect();
        let (unlocked, locked) = self.daemon.keyring.lock().await.search(&query, Some(&self.id));
        unlocked.into_iter().chain(locked).map(|(c, i)| op(&item_path(&c, &i))).collect()
    }

    async fn create_item(
        &self,
        properties: HashMap<String, OwnedVariant>,
        secret: WireSecret,
        replace: bool,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        let (plain, content_type) = self.daemon.decode_secret(&secret, sender(&header).as_deref())?;
        let caller = self.daemon.caller(&header).await;
        let label = prop_string(&properties, PROP_ITEM_LABEL);
        let attributes = prop_attributes(&properties);
        if self.daemon.keyring.lock().await.collection_locked(&self.id) {
            let new = NewItem { label, attributes, secret: plain, content_type, replace };
            let action = PromptAction::CreateItem { collection: self.id.clone(), new, caller };
            let prompt = PromptObj::register(&self.daemon, sender(&header), action).await?;
            return Ok((no_prompt(), prompt));
        }
        let new = NewItem { label, attributes, secret: plain, content_type, replace };
        let path = self.daemon.create_item(&self.id, new, &caller).await?;
        Ok((path, no_prompt()))
    }

    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        self.daemon.keyring.lock().await.items_in(&self.id).into_iter().map(|i| op(&item_path(&self.id, &i))).collect()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        self.daemon.keyring.lock().await.collection(&self.id).map(|c| c.label.clone()).unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&mut self, value: String) -> zbus::fdo::Result<()> {
        // Kept locally until the next refresh: the registry keeps the label a
        // collection was created with.
        self.daemon.keyring.lock().await.set_collection_label(&self.id, &value);
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.daemon.keyring.lock().await.collection_locked(&self.id)
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        self.daemon.keyring.lock().await.collection(&self.id).map_or(0, |c| c.created)
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        self.daemon.keyring.lock().await.collection(&self.id).map_or(0, |c| c.modified)
    }

    #[zbus(signal)]
    pub async fn item_created(emitter: &SignalEmitter<'_>, item: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn item_deleted(emitter: &SignalEmitter<'_>, item: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn item_changed(emitter: &SignalEmitter<'_>, item: OwnedObjectPath) -> zbus::Result<()>;
}

// --- Item -----------------------------------------------------------------------

pub struct ItemObj {
    pub daemon: Arc<Daemon>,
    pub id: String,
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ItemObj {
    async fn delete(&self, #[zbus(header)] header: Header<'_>) -> Result<OwnedObjectPath, SecretError> {
        let caller = self.daemon.caller(&header).await;
        self.daemon.authorize(&caller, &self.id, "delete").await?;
        self.daemon.delete_item(&self.id).await?;
        Ok(no_prompt())
    }

    async fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(SecretStruct,), SecretError> {
        self.daemon.session(session.as_str(), sender(&header).as_deref())?;
        if self.daemon.keyring.lock().await.item_locked(&self.id) {
            return Err(SecretError::IsLocked("the item is locked".into()));
        }
        let caller = self.daemon.caller(&header).await;
        self.daemon.authorize(&caller, &self.id, "read").await?;
        let (secret, ct) = self
            .daemon
            .keyring
            .lock()
            .await
            .item(&self.id)
            .map(|i| (i.secret.clone(), i.content_type.clone()))
            .ok_or_else(|| SecretError::IsLocked("the item is locked".into()))?;
        self.daemon.touch();
        self.daemon.encode_secret(session.as_str(), &secret, &ct).map(|w| (SecretStruct::from(w),))
    }

    async fn set_secret(&self, secret: WireSecret, #[zbus(header)] header: Header<'_>) -> Result<(), SecretError> {
        let (plain, content_type) = self.daemon.decode_secret(&secret, sender(&header).as_deref())?;
        let caller = self.daemon.caller(&header).await;
        self.daemon.authorize(&caller, &self.id, "change").await?;
        self.daemon
            .update_item(&self.id, move |i| {
                i.secret = plain;
                i.content_type = content_type;
            })
            .await
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.daemon.keyring.lock().await.item_locked(&self.id)
    }

    #[zbus(property)]
    async fn attributes(&self) -> HashMap<String, String> {
        self.daemon
            .keyring
            .lock()
            .await
            .item(&self.id)
            .map(|i| i.attributes.clone().into_iter().collect())
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_attributes(
        &mut self,
        value: HashMap<String, String>,
        #[zbus(header)] header: Option<Header<'_>>,
    ) -> zbus::fdo::Result<()> {
        self.edit(header, "change", move |i| i.attributes = value.into_iter().collect()).await
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        self.daemon.keyring.lock().await.item(&self.id).map(|i| i.label.clone()).unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&mut self, value: String, #[zbus(header)] header: Option<Header<'_>>) -> zbus::fdo::Result<()> {
        self.edit(header, "rename", move |i| i.label = value).await
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        self.daemon.keyring.lock().await.item(&self.id).map_or(0, |i| i.created)
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        self.daemon.keyring.lock().await.item(&self.id).map_or(0, |i| i.modified)
    }
}

impl ItemObj {
    async fn edit(
        &self,
        header: Option<Header<'_>>,
        action: &str,
        f: impl FnOnce(&mut crate::model::ItemData),
    ) -> zbus::fdo::Result<()> {
        // Properties.Set always passes its header; without one there is no caller to check.
        let Some(header) = header else { return Err(zbus::fdo::Error::AccessDenied("no caller".into())) };
        let caller = self.daemon.caller(&header).await;
        let to_fdo = |e: SecretError| zbus::fdo::Error::Failed(format!("{e:?}"));
        self.daemon.authorize(&caller, &self.id, action).await.map_err(to_fdo)?;
        self.daemon.update_item(&self.id, f).await.map_err(to_fdo)
    }
}

// --- Session --------------------------------------------------------------------

pub struct SessionObj {
    pub daemon: Arc<Daemon>,
    pub path: String,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SessionObj {
    async fn close(
        &self,
        #[zbus(object_server)] server: &zbus::ObjectServer,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        {
            let mut sessions = lock(&self.daemon.sessions);
            // Only the bus name that opened the session may close it.
            if sessions.get(&self.path).is_some_and(|s| Some(s.owner.as_str()) != sender(&header).as_deref()) {
                return Err(zbus::fdo::Error::AccessDenied("the session belongs to another client".into()));
            }
            sessions.remove(&self.path);
        }
        server.remove::<SessionObj, _>(self.path.as_str()).await?;
        Ok(())
    }
}

// --- Prompt ---------------------------------------------------------------------

pub enum PromptAction {
    Unlock { objects: Vec<OwnedObjectPath> },
    CreateItem { collection: String, new: NewItem, caller: String },
    CreateCollection { label: String },
}

/// What a prompt will do, until it runs, is dismissed or is cancelled. A
/// started prompt's task shares it, so a departed client's action can still
/// be dropped while the password is being asked for.
type ActionSlot = Arc<std::sync::Mutex<Option<PromptAction>>>;

pub struct PromptObj {
    daemon: Arc<Daemon>,
    path: String,
    action: ActionSlot,
}

impl PromptAction {
    /// The result to report when the prompt is dismissed. It must have the
    /// type the successful result would have (`ao` for an unlock, `o`
    /// otherwise): libsecret rejects anything else and then never completes.
    #[expect(clippy::expect_used, reason = "plain variants without file descriptors always convert")]
    fn dismissed_result(&self) -> OwnedVariant {
        let v = match self {
            PromptAction::Unlock { .. } => Variant::from(Vec::<OwnedObjectPath>::new()),
            PromptAction::CreateItem { .. } | PromptAction::CreateCollection { .. } => Variant::from(no_prompt()),
        };
        OwnedVariant::try_from(v).expect("plain variant")
    }
}

impl PromptObj {
    pub async fn register(
        daemon: &Arc<Daemon>,
        owner: Option<String>,
        action: PromptAction,
    ) -> Result<OwnedObjectPath, SecretError> {
        let owner = owner.unwrap_or_default();
        let seq = daemon.next_id();
        let path = format!("{SERVICE_PATH}/prompt/p{seq}");
        // The slot is reserved in the same locked section that checks the cap,
        // so concurrent registrations cannot exceed it. A client that is over
        // the cap loses its oldest prompt that has not started.
        let victim = {
            let mut prompts = lock(&daemon.prompts);
            let held = prompts.iter().filter(|p| p.owner == owner).map(|p| (p.seq, p.pinned()));
            let victim = match prompt_slot(held, PROMPTS_PER_OWNER) {
                PromptSlot::Free => None,
                PromptSlot::Evict(oldest) => {
                    let at = prompts.iter().position(|p| p.seq == oldest);
                    at.map(|at| prompts.remove(at))
                }
                PromptSlot::Full => return Err(SecretError::Failed("too many outstanding prompts".into())),
            };
            prompts.push(PromptEntry { seq, path: path.clone(), owner, started: false, registered: false });
            victim
        };
        if let Some(entry) = victim {
            PromptObj::dismiss_pending(daemon, &entry.path).await;
        }
        let obj = PromptObj {
            daemon: daemon.clone(),
            path: path.clone(),
            action: Arc::new(std::sync::Mutex::new(Some(action))),
        };
        #[cfg(test)]
        daemon.before_adding().await;
        let server = daemon.conn().object_server();
        // Adding fails only for an invalid path; it is cleaned up like a prompt
        // dropped with its client while the object was being added, which is
        // no longer tracked and so is removed again (dropping what it holds).
        let added = server.at(path.as_str(), obj).await;
        let tracked = added.is_ok() && {
            let mut prompts = lock(&daemon.prompts);
            prompts.iter_mut().find(|p| p.seq == seq).map(|e| e.registered = true).is_some()
        };
        if !tracked {
            lock(&daemon.prompts).retain(|p| p.seq != seq);
            let _ = server.remove::<PromptObj, _>(path.as_str()).await;
            let dismissed = SecretError::Failed("the prompt was dismissed".into());
            return Err(added.err().map_or(dismissed, SecretError::ZBus));
        }
        Ok(op(&path))
    }

    /// Dismisses an evicted prompt, dropping (and so zeroizing) what it holds.
    /// Only registered prompts are evicted, so the object is on the bus.
    async fn dismiss_pending(daemon: &Arc<Daemon>, path: &str) {
        // Already gone (finished or removed concurrently): nothing to signal.
        let Ok(iface) = daemon.conn().object_server().interface::<_, PromptObj>(path).await else { return };
        let taken = lock(&iface.get().await.action).take();
        if let Some(action) = taken {
            PromptObj::finish(daemon.clone(), path.to_owned(), true, action.dismissed_result()).await;
        }
    }

    /// Drops the action of a prompt whose client left the bus, started or
    /// not, and removes the object. Nobody is left to tell.
    pub async fn cancel(daemon: &Daemon, path: &str) {
        let server = daemon.conn().object_server();
        if let Ok(iface) = server.interface::<_, PromptObj>(path).await {
            drop(lock(&iface.get().await.action).take());
        }
        let _ = server.remove::<PromptObj, _>(path).await;
    }

    async fn finish(daemon: Arc<Daemon>, path: String, dismissed: bool, result: OwnedVariant) {
        lock(&daemon.prompts).retain(|p| p.path != path);
        let _ = PromptObj::completed(&emitter(daemon.conn(), &path), dismissed, result).await;
        let _ = daemon.conn().object_server().remove::<PromptObj, _>(path.as_str()).await;
    }
}

/// The prompt at `path`, when `sender` may start or dismiss it: only the bus
/// name that asked for it (prompt paths are predictable), and only while it
/// is tracked (an evicted prompt cannot start).
fn controlled<'a>(
    prompts: &'a mut [PromptEntry],
    path: &str,
    sender: Option<&str>,
) -> Result<&'a mut PromptEntry, SecretError> {
    match prompts.iter_mut().find(|p| p.path == path) {
        None => Err(SecretError::Failed("the prompt was dismissed".into())),
        Some(p) if Some(p.owner.as_str()) == sender => Ok(p),
        Some(_) => Err(SecretError::AccessDenied("the prompt belongs to another client".into())),
    }
}

/// Takes a started prompt's action to run it. `None` when it was dismissed,
/// or when its client left the bus (`drop_owner` stops tracking the prompt
/// before it drops the action): then nothing runs.
fn claim_action(prompts: &std::sync::Mutex<Vec<PromptEntry>>, path: &str, slot: &ActionSlot) -> Option<PromptAction> {
    // Under the prompts lock, so `drop_owner` either ran before (nothing
    // runs) or after the action was claimed.
    let prompts = lock(prompts);
    let action = lock(slot).take();
    action.filter(|_| prompts.iter().any(|p| p.path == path))
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptObj {
    async fn prompt(&self, _window_id: &str, #[zbus(header)] header: Header<'_>) -> Result<(), SecretError> {
        let dismissed = {
            let mut prompts = lock(&self.daemon.prompts);
            let entry = controlled(&mut prompts, &self.path, sender(&header).as_deref())?;
            let unused = lock(&self.action).as_ref().filter(|_| !entry.started).map(PromptAction::dismissed_result);
            let Some(dismissed) = unused else {
                return Err(SecretError::Failed("the prompt was already used".into()));
            };
            entry.started = true;
            dismissed
        };
        let daemon = self.daemon.clone();
        let path = self.path.clone();
        let slot = self.action.clone();
        // The reply must not wait for the user; the outcome goes out as the
        // Completed signal.
        tokio::spawn(async move {
            let unlocked = daemon.unlock_interactive().await;
            // Gone when the prompt was dismissed meanwhile (which signalled)
            // or its client left the bus (nobody to tell): nothing runs.
            let Some(action) = claim_action(&daemon.prompts, &path, &slot) else { return };
            if !unlocked {
                drop(action);
                return PromptObj::finish(daemon, path, true, dismissed).await;
            }
            let result: SResult<OwnedVariant> = async {
                match action {
                    PromptAction::Unlock { objects } => {
                        OwnedVariant::try_from(Variant::from(objects)).map_err(SecretError::ZBus)
                    }
                    PromptAction::CreateItem { collection, new, caller } => {
                        let p = daemon.create_item(&collection, new, &caller).await?;
                        OwnedVariant::try_from(Variant::from(p)).map_err(SecretError::ZBus)
                    }
                    PromptAction::CreateCollection { label } => {
                        let p = daemon.create_collection(&label).await?;
                        OwnedVariant::try_from(Variant::from(p)).map_err(SecretError::ZBus)
                    }
                }
            }
            .await;
            match result {
                Ok(v) => PromptObj::finish(daemon, path, false, v).await,
                Err(e) => {
                    tracing::warn!("prompt action failed: {e:?}");
                    PromptObj::finish(daemon, path, true, dismissed).await
                }
            }
        });
        Ok(())
    }

    async fn dismiss(&self, #[zbus(header)] header: Header<'_>) -> Result<(), SecretError> {
        controlled(&mut lock(&self.daemon.prompts), &self.path, sender(&header).as_deref())?;
        if let Some(action) = lock(&self.action).take() {
            tokio::spawn(PromptObj::finish(self.daemon.clone(), self.path.clone(), true, action.dismissed_result()));
        }
        Ok(())
    }

    #[zbus(signal)]
    async fn completed(emitter: &SignalEmitter<'_>, dismissed: bool, result: OwnedVariant) -> zbus::Result<()>;
}

// --- bwss control interface -----------------------------------------------------

pub const CONTROL_PATH: &str = "/io/github/dynamotn/bwss";
pub const CONTROL_NAME: &str = "io.github.dynamotn.bwss";

pub struct ControlObj {
    pub daemon: Arc<Daemon>,
}

#[interface(name = "io.github.dynamotn.bwss.Control1")]
impl ControlObj {
    /// For `bwss unlock --password-stdin` only: any other executable is
    /// refused before the password is tried. Failures are slowed down so that
    /// the method cannot be used to guess the password quickly.
    async fn unlock_with_password(
        &self,
        password: String,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), SecretError> {
        let password = Zeroizing::new(password);
        let caller = self.daemon.caller(&header).await;
        if !crate::acl::is_own_executable(&caller) {
            tracing::warn!(caller = %caller, "refused a password sent by another executable");
            return Err(SecretError::AccessDenied(format!(
                "only the bwss CLI may send the master password; {caller} may not (use `bwss unlock`)"
            )));
        }
        self.daemon.unlock_with_password_throttled(&password).await.map_err(|e| SecretError::Failed(e.to_string()))
    }

    /// Asks for the master password through the daemon's own prompter, so no
    /// password crosses the bus. Returns whether the keyring is unlocked.
    async fn unlock_interactive(&self) -> bool {
        self.daemon.unlock_interactive_throttled().await
    }

    async fn lock(&self) {
        self.daemon.lock().await;
    }

    async fn sync(&self) -> Result<(), SecretError> {
        self.daemon.refresh().await;
        Ok(())
    }

    /// (unlocked, item count, backend description)
    async fn status(&self) -> (bool, u32, String) {
        let (unlocked, items) = {
            let k = self.daemon.keyring.lock().await;
            (k.is_unlocked(), u32::try_from(k.item_refs().len()).unwrap_or(u32::MAX))
        };
        (unlocked, items, self.daemon.backend.describe().await)
    }
}

/// Registers the static objects; collections and items follow the keyring.
pub async fn serve(daemon: &Arc<Daemon>) -> zbus::Result<()> {
    let server = daemon.conn().object_server();
    server.at(SERVICE_PATH, ServiceObj { daemon: daemon.clone() }).await?;
    server.at(CONTROL_PATH, ControlObj { daemon: daemon.clone() }).await?;
    watch_departures(daemon).await?;
    daemon.sync_objects().await
}

/// Pins the process of a client when it joins the bus, and frees its
/// sessions, prompts and pin when it leaves.
async fn watch_departures(daemon: &Arc<Daemon>) -> zbus::Result<()> {
    use zbus::export::futures_core::Stream;
    let bus = zbus::fdo::DBusProxy::new(daemon.conn()).await?;
    let stream = bus.receive_name_owner_changed().await?;
    let daemon = daemon.clone();
    tokio::spawn(async move {
        let mut stream = std::pin::pin!(stream);
        while let Some(signal) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
            let Ok(args) = signal.args() else { continue };
            let name = args.name().as_str();
            if !name.starts_with(':') {
                continue;
            }
            if args.new_owner().is_none() {
                daemon.drop_owner(name).await;
            } else {
                // A new connection (a unique name never changes owner): pin
                // its process now, not at its first call.
                let (daemon, name) = (daemon.clone(), name.to_owned());
                tokio::spawn(async move { daemon.name_appeared(&name).await });
            }
        }
    });
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn entry(path: &str, owner: &str) -> PromptEntry {
        PromptEntry { seq: 1, path: path.into(), owner: owner.into(), started: true, registered: true }
    }

    fn slot() -> ActionSlot {
        Arc::new(std::sync::Mutex::new(Some(PromptAction::CreateCollection { label: "x".into() })))
    }

    #[test]
    fn only_the_owner_of_a_tracked_prompt_may_control_it() {
        let mut prompts = [entry("/p0", ":1.1"), entry("/p1", ":1.1")];
        let own = controlled(&mut prompts, "/p1", Some(":1.1")).unwrap();
        assert_eq!(own.path, "/p1", "the entry at that path");
        own.started = false;
        let started: Vec<bool> = prompts.iter().map(|p| p.started).collect();
        assert_eq!(started, [true, false], "and it can be changed in place");
        let mut tried = |path: &str, sender| format!("{:?}", controlled(&mut prompts, path, sender).map(|p| p.seq));
        for sender in [Some(":1.2"), None] {
            assert_eq!(tried("/p1", sender), r#"Err(AccessDenied("the prompt belongs to another client"))"#);
        }
        // No longer tracked (finished, evicted, or its client left): nobody may.
        assert_eq!(tried("/p2", Some(":1.1")), r#"Err(Failed("the prompt was dismissed"))"#);
    }

    #[test]
    fn a_started_prompt_runs_only_while_it_is_tracked() {
        let prompts = std::sync::Mutex::new(vec![entry("/p1", ":1.1")]);
        let held = slot();
        assert!(claim_action(&prompts, "/p1", &held).is_some());
        assert!(claim_action(&prompts, "/p1", &held).is_none(), "taken once");

        // The client left: `drop_owner` stopped tracking the prompt before
        // `cancel` reached the action. The unlock returning now runs nothing.
        let held = slot();
        lock(&prompts).retain(|p| p.owner != ":1.1");
        assert!(claim_action(&prompts, "/p1", &held).is_none());
        assert!(lock(&held).is_none(), "and the action is dropped");
    }

    use crate::backend::memory::MemoryBackend;
    use crate::config::Config;
    use crate::daemon::{Gate, SESSIONS_PER_OWNER, SESSIONS_TOTAL};
    use crate::keyring::Keyring;
    use crate::prompter::Prompter;
    use std::time::Duration;
    use zbus::Connection;
    use zbus::export::futures_core::Stream;

    /// The bus driver as far as the daemon asks it: which names are gone.
    struct Driver {
        gone: Vec<String>,
    }

    #[zbus::interface(name = "org.freedesktop.DBus")]
    impl Driver {
        async fn name_has_owner(&self, name: &str) -> bool {
            !self.gone.iter().any(|g| g == name)
        }
    }

    /// An unlocked daemon (memory backend) on one end of a socket pair. The
    /// other end plays the bus driver, with the names in `gone` no longer on
    /// the bus, and gets the daemon's signals.
    async fn daemon_on_a_socket(gone: &[&str]) -> (Arc<Daemon>, Connection) {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        let driver = Driver { gone: gone.iter().map(|g| (*g).to_owned()).collect() };
        let peer = zbus::connection::Builder::unix_stream(a)
            .server(zbus::Guid::generate())
            .p2p()
            .serve_at("/org/freedesktop/DBus", driver)
            .build();
        let (peer, conn) = tokio::try_join!(peer, zbus::connection::Builder::unix_stream(b).p2p().build()).unwrap();
        let backend = Arc::new(MemoryBackend::new("pw"));
        let d = Daemon::new(
            Keyring::new(None, None),
            backend,
            Prompter::new("false", Duration::from_secs(1)),
            Config::default(),
        );
        d.set_connection(conn);
        d.unlock_with_password("pw").await.unwrap();
        (d, peer)
    }

    /// The next message the peer got.
    async fn next_message(stream: &mut zbus::MessageStream) -> zbus::Message {
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_next(cx)).await.unwrap().unwrap()
    }

    /// The next message the peer got, a signal naming one object: (member, path).
    async fn next_signal(stream: &mut zbus::MessageStream) -> (String, String) {
        let msg = next_message(stream).await;
        assert_eq!(msg.header().message_type(), zbus::message::Type::Signal);
        let (path,): (OwnedObjectPath,) = msg.body().deserialize().unwrap();
        (msg.header().member().unwrap().to_string(), path.to_string())
    }

    async fn on_bus<I: zbus::object_server::Interface>(d: &Daemon, path: &str) -> bool {
        d.conn().object_server().interface::<_, I>(path).await.is_ok()
    }

    fn the_err<T: std::fmt::Debug>(r: SResult<T>) -> String {
        format!("{:?}", r.unwrap_err())
    }

    #[tokio::test]
    async fn sessions_are_put_on_the_bus_and_capped_per_client() {
        let (d, _peer) = daemon_on_a_socket(&[]).await;
        let refused = open_tracked_session(&d, "rot13", &[], ":1.7".into()).await;
        assert!(the_err(refused).starts_with("NotSupported("));
        let (output, first) = open_tracked_session(&d, "plain", &[], ":1.7".into()).await.unwrap();
        assert!(output.is_empty(), "plain needs no key exchange");
        assert!(on_bus::<SessionObj>(&d, &first).await);
        let mut newest = String::new();
        for _ in 0..SESSIONS_PER_OWNER {
            newest = open_tracked_session(&d, "plain", &[], ":1.7".into()).await.unwrap().1;
        }
        // The client's oldest session made room, and its object is gone too.
        assert!(!lock(&d.sessions).contains_key(&first));
        assert!(!on_bus::<SessionObj>(&d, &first).await);
        assert!(on_bus::<SessionObj>(&d, &newest).await);
        assert_eq!(lock(&d.sessions).len(), SESSIONS_PER_OWNER);
    }

    #[tokio::test]
    async fn a_full_daemon_frees_the_sessions_and_prompts_of_departed_clients_first() {
        let (d, _peer) = daemon_on_a_socket(&[":2.5"]).await;
        // Every other client holds as many sessions as it may, filling the
        // total; one of them has left the bus, and one has no bus name.
        let owners: Vec<String> = std::iter::once(String::new()).chain((1..64).map(|n| format!(":2.{n}"))).collect();
        for (n, owner) in owners.iter().enumerate() {
            for k in 0..SESSIONS_PER_OWNER {
                let seq = (n * SESSIONS_PER_OWNER + k) as u64;
                let session = crate::session::Session::open("plain", &[]).unwrap().0;
                let open = Arc::new(OpenSession { seq, owner: owner.clone(), session });
                assert!(d.admit_session(open, &format!("/held/s{seq}"), false).1);
            }
        }
        let left =
            PromptEntry { seq: 1, path: "/held/p1".into(), owner: ":2.5".into(), started: false, registered: false };
        lock(&d.prompts).push(left);
        assert_eq!(lock(&d.sessions).len(), SESSIONS_TOTAL);
        assert!(d.known_owners().contains(":2.5") && d.known_owners().contains(""));

        let (_, path) = open_tracked_session(&d, "plain", &[], ":1.9".into()).await.unwrap();
        let sessions = lock(&d.sessions);
        assert!(sessions.contains_key(&path));
        assert!(!sessions.values().any(|s| s.owner == ":2.5"), "the departed client's sessions are freed");
        assert_eq!(sessions.len(), SESSIONS_TOTAL - SESSIONS_PER_OWNER + 1, "and nobody else lost one");
        drop(sessions);
        assert!(lock(&d.prompts).is_empty(), "and its prompt");
    }

    #[tokio::test]
    async fn a_session_whose_client_leaves_while_its_object_is_added_is_removed_again() {
        let (d, _peer) = daemon_on_a_socket(&[]).await;
        let gate = Arc::new(Gate::default());
        *lock(&d.adding) = Some(gate.clone());
        let opening = tokio::spawn({
            let d = d.clone();
            async move { open_tracked_session(&d, "plain", &[], ":1.7".into()).await }
        });
        gate.entered.notified().await;
        assert_eq!(lock(&d.sessions).len(), 1, "admitted, its object not yet added");
        d.drop_owner(":1.7").await;
        gate.release.notify_one();
        assert_eq!(the_err(opening.await.unwrap()), r#"Failed("the session was closed while opening")"#);
        assert!(lock(&d.sessions).is_empty());
        let path = format!("{SERVICE_PATH}/session/s{}", d.next_id() - 1);
        assert!(!on_bus::<SessionObj>(&d, &path).await, "no object is left behind");
    }

    fn unlock_action() -> PromptAction {
        PromptAction::Unlock { objects: vec![] }
    }

    #[tokio::test]
    async fn the_oldest_idle_prompt_of_a_client_at_its_cap_is_dismissed() {
        let (d, peer) = daemon_on_a_socket(&[]).await;
        let mut signals = zbus::MessageStream::from(&peer);
        let mut paths = vec![];
        for _ in 0..PROMPTS_PER_OWNER {
            paths.push(PromptObj::register(&d, Some(":1.7".into()), unlock_action()).await.unwrap().to_string());
        }
        let other = PromptObj::register(&d, Some(":1.8".into()), unlock_action()).await.unwrap();
        let newest = PromptObj::register(&d, Some(":1.7".into()), unlock_action()).await.unwrap();
        // The oldest told its client it was dismissed, with an empty unlock result.
        let oldest = paths.first().unwrap();
        let completed = next_message(&mut signals).await;
        assert_eq!(completed.header().member().unwrap().as_str(), "Completed");
        assert_eq!(completed.header().path().unwrap().as_str(), oldest);
        let (dismissed, result): (bool, OwnedVariant) = completed.body().deserialize().unwrap();
        assert!(dismissed);
        assert_eq!(Vec::<OwnedObjectPath>::try_from(result).unwrap(), Vec::<OwnedObjectPath>::new());
        assert!(!on_bus::<PromptObj>(&d, oldest).await);
        for p in [paths.last().unwrap().as_str(), other.as_str(), newest.as_str()] {
            assert!(on_bus::<PromptObj>(&d, p).await, "{p}");
        }
        assert_eq!(lock(&d.prompts).iter().filter(|p| p.owner == ":1.7").count(), PROMPTS_PER_OWNER);
    }

    #[tokio::test]
    async fn a_client_whose_prompts_all_run_gets_no_more() {
        let (d, _peer) = daemon_on_a_socket(&[]).await;
        for _ in 0..PROMPTS_PER_OWNER {
            PromptObj::register(&d, Some(":1.7".into()), unlock_action()).await.unwrap();
        }
        for p in lock(&d.prompts).iter_mut() {
            p.started = true;
        }
        let refused = PromptObj::register(&d, Some(":1.7".into()), unlock_action()).await;
        assert_eq!(the_err(refused), r#"Failed("too many outstanding prompts")"#);
        assert_eq!(lock(&d.prompts).len(), PROMPTS_PER_OWNER);
    }

    #[tokio::test]
    async fn an_evicted_prompt_already_being_dismissed_is_not_signalled_twice() {
        let (d, _peer) = daemon_on_a_socket(&[]).await;
        let mut paths = vec![];
        for _ in 0..PROMPTS_PER_OWNER {
            paths.push(PromptObj::register(&d, Some(":1.7".into()), unlock_action()).await.unwrap().to_string());
        }
        // `Dismiss` took the oldest's action; its own `finish` has not run yet.
        let oldest = paths.first().unwrap();
        let iface = d.conn().object_server().interface::<_, PromptObj>(oldest.as_str()).await.unwrap();
        let taken = lock(&iface.get().await.action).take();
        assert!(taken.is_some());
        PromptObj::register(&d, Some(":1.7".into()), unlock_action()).await.unwrap();
        // Evicted, but left to the pending `finish`: no second Completed.
        assert!(!lock(&d.prompts).iter().any(|p| &p.path == oldest));
        assert!(on_bus::<PromptObj>(&d, oldest).await, "only that finish removes it");
    }

    #[tokio::test]
    async fn a_prompt_whose_client_leaves_while_its_object_is_added_is_removed_again() {
        let (d, _peer) = daemon_on_a_socket(&[]).await;
        let others = PromptObj::register(&d, Some(":1.8".into()), unlock_action()).await.unwrap();
        let gate = Arc::new(Gate::default());
        *lock(&d.adding) = Some(gate.clone());
        let registering = tokio::spawn({
            let d = d.clone();
            async move { PromptObj::register(&d, Some(":1.7".into()), unlock_action()).await }
        });
        gate.entered.notified().await;
        assert_eq!(lock(&d.prompts).len(), 2, "a slot is reserved, the object not yet added");
        d.drop_owner(":1.7").await;
        gate.release.notify_one();
        assert_eq!(the_err(registering.await.unwrap()), r#"Failed("the prompt was dismissed")"#);
        let path = format!("{SERVICE_PATH}/prompt/p{}", d.next_id() - 1);
        assert!(!on_bus::<PromptObj>(&d, &path).await, "no object is left behind");
        // Another client's prompt is untouched.
        let tracked: Vec<String> = lock(&d.prompts).iter().map(|p| p.path.clone()).collect();
        assert_eq!(tracked, [others.to_string()]);
        assert!(on_bus::<PromptObj>(&d, others.as_str()).await);
    }

    #[tokio::test]
    async fn a_departed_clients_prompts_are_cancelled_and_removed() {
        let (d, _peer) = daemon_on_a_socket(&[]).await;
        let path = PromptObj::register(&d, Some(":1.7".into()), unlock_action()).await.unwrap();
        let iface = d.conn().object_server().interface::<_, PromptObj>(path.as_str()).await.unwrap();
        d.drop_owner(":1.7").await;
        assert!(lock(&iface.get().await.action).is_none(), "its action is dropped");
        assert!(!on_bus::<PromptObj>(&d, path.as_str()).await);
        assert!(lock(&d.prompts).is_empty());
    }

    fn item(label: &str) -> NewItem {
        NewItem {
            label: label.into(),
            attributes: [("k".to_owned(), label.to_owned())].into_iter().collect(),
            secret: Zeroizing::new(b"s".to_vec()),
            content_type: "text/plain".into(),
            replace: false,
        }
    }

    #[tokio::test]
    async fn objects_and_signals_follow_the_keyring() {
        let (d, peer) = daemon_on_a_socket(&[]).await;
        let mut signals = zbus::MessageStream::from(&peer);
        let git = "/usr/bin/git";
        d.sync_objects().await.unwrap();
        for c in [
            collection_path(LOGIN_COLLECTION),
            collection_path(SESSION_COLLECTION),
            crate::daemon::DEFAULT_ALIAS_PATH.into(),
        ] {
            assert!(on_bus::<CollectionObj>(&d, &c).await, "{c}");
        }

        let work = d.create_collection("Work").await.unwrap();
        assert_eq!(next_signal(&mut signals).await, ("CollectionCreated".into(), work.to_string()));
        assert!(on_bus::<CollectionObj>(&d, work.as_str()).await);
        let vpn = d.create_item("work", item("vpn"), git).await.unwrap();
        assert_eq!(next_signal(&mut signals).await, ("ItemCreated".into(), vpn.to_string()));
        assert!(on_bus::<ItemObj>(&d, vpn.as_str()).await);
        let vpn_id = parse_path(vpn.as_str()).unwrap().1.unwrap();
        d.update_item(&vpn_id, |i| i.label = "VPN".into()).await.unwrap();
        assert_eq!(next_signal(&mut signals).await, ("ItemChanged".into(), vpn.to_string()));
        d.delete_item(&vpn_id).await.unwrap();
        assert_eq!(next_signal(&mut signals).await, ("ItemDeleted".into(), vpn.to_string()));
        assert!(!on_bus::<ItemObj>(&d, vpn.as_str()).await);

        let wifi = d.create_item("work", item("wifi"), git).await.unwrap();
        assert_eq!(next_signal(&mut signals).await, ("ItemCreated".into(), wifi.to_string()));
        let wifi_id = parse_path(wifi.as_str()).unwrap().1.unwrap();
        d.delete_collection("work", std::slice::from_ref(&wifi_id)).await.unwrap();
        assert_eq!(next_signal(&mut signals).await, ("CollectionDeleted".into(), work.to_string()));
        assert_eq!(next_signal(&mut signals).await, ("ItemDeleted".into(), wifi.to_string()));
        assert!(!on_bus::<CollectionObj>(&d, work.as_str()).await && !on_bus::<ItemObj>(&d, wifi.as_str()).await);

        // An object update that fails does not hold back the signals.
        let mail = d.create_item(LOGIN_COLLECTION, item("mail"), git).await.unwrap();
        assert_eq!(next_signal(&mut signals).await, ("ItemCreated".into(), mail.to_string()));
        d.conn().object_server().remove::<ItemObj, _>(mail.as_str()).await.unwrap();
        d.delete_item(&parse_path(mail.as_str()).unwrap().1.unwrap()).await.unwrap();
        assert_eq!(next_signal(&mut signals).await, ("ItemDeleted".into(), mail.to_string()));
    }
}
