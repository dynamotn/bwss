//! The org.freedesktop.Secret.* interfaces. Thin wrappers over `Daemon`.

use std::collections::HashMap;
use std::sync::Arc;

use zbus::{OwnedObjectPath, OwnedVariant, Variant, interface, message::Header, object_server::SignalEmitter};
use zeroize::Zeroizing;

use crate::acl::caller_executable;
use crate::daemon::{
    DEFAULT_ALIAS_PATH, Daemon, NewItem, OpenSession, SERVICE_PATH, SResult, SecretError, WireSecret, collection_path,
    item_path, no_prompt, op, parse_path,
};
use crate::model::{Attributes, LOGIN_COLLECTION, SESSION_COLLECTION};
use crate::session::Session;

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
        let (session, output) =
            Session::open(algorithm, &bytes).map_err(|e| SecretError::NotSupported(e.to_string()))?;
        let path = format!("{SERVICE_PATH}/session/s{}", self.daemon.next_id());
        let owner = sender(&header).unwrap_or_default();
        {
            let mut sessions = self.daemon.sessions.lock().unwrap();
            // Bound memory use by clients that never close their sessions.
            if sessions.len() >= 4096
                && let Some(k) = sessions.keys().next().cloned()
            {
                sessions.remove(&k);
            }
            sessions.insert(path.clone(), Arc::new(OpenSession { owner, session }));
        }
        self.daemon
            .conn()
            .object_server()
            .at(path.as_str(), SessionObj { daemon: self.daemon.clone(), path: path.clone() })
            .await
            .map_err(SecretError::ZBus)?;
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
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        if alias == "default" {
            return Ok((op(&collection_path(LOGIN_COLLECTION)), no_prompt()));
        }
        let label = prop_string(&properties, PROP_COLLECTION_LABEL);
        if !self.daemon.keyring.lock().await.is_unlocked() {
            let prompt = PromptObj::register(&self.daemon, PromptAction::CreateCollection { label }).await?;
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
        let prompt = PromptObj::register(&self.daemon, PromptAction::Unlock { objects: pending }).await?;
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
        let caller = caller_executable(self.daemon.conn(), &header).await;
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
        let caller = caller_executable(self.daemon.conn(), &header).await;
        let ids = self.daemon.keyring.lock().await.items_in(&self.id);
        for id in ids {
            self.daemon.authorize(&caller, &id, "delete").await?;
        }
        self.daemon.delete_collection(&self.id).await?;
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
        let caller = caller_executable(self.daemon.conn(), &header).await;
        let label = prop_string(&properties, PROP_ITEM_LABEL);
        let attributes = prop_attributes(&properties);
        if self.daemon.keyring.lock().await.collection_locked(&self.id) {
            let new = NewItem { label, attributes, secret: plain, content_type, replace };
            let action = PromptAction::CreateItem { collection: self.id.clone(), new, caller };
            let prompt = PromptObj::register(&self.daemon, action).await?;
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
        // Labels are kept locally; the Bitwarden folder name is the collection id.
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
        let caller = caller_executable(self.daemon.conn(), &header).await;
        self.daemon.authorize(&caller, &self.id, "delete").await?;
        self.daemon.delete_item(&self.id).await?;
        Ok(no_prompt())
    }

    async fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<WireSecret, SecretError> {
        self.daemon.session(session.as_str(), sender(&header).as_deref())?;
        if self.daemon.keyring.lock().await.item_locked(&self.id) {
            return Err(SecretError::IsLocked("the item is locked".into()));
        }
        let caller = caller_executable(self.daemon.conn(), &header).await;
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
        self.daemon.encode_secret(session.as_str(), &secret, &ct)
    }

    async fn set_secret(&self, secret: WireSecret, #[zbus(header)] header: Header<'_>) -> Result<(), SecretError> {
        let (plain, content_type) = self.daemon.decode_secret(&secret, sender(&header).as_deref())?;
        let caller = caller_executable(self.daemon.conn(), &header).await;
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
        let caller = match &header {
            Some(h) => caller_executable(self.daemon.conn(), h).await,
            None => crate::acl::UNKNOWN.to_owned(),
        };
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
    async fn close(&self, #[zbus(object_server)] server: &zbus::ObjectServer) -> zbus::fdo::Result<()> {
        self.daemon.sessions.lock().unwrap().remove(&self.path);
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

pub struct PromptObj {
    daemon: Arc<Daemon>,
    path: String,
    action: std::sync::Mutex<Option<PromptAction>>,
}

impl PromptObj {
    pub async fn register(daemon: &Arc<Daemon>, action: PromptAction) -> Result<OwnedObjectPath, SecretError> {
        let path = format!("{SERVICE_PATH}/prompt/p{}", daemon.next_id());
        let obj = PromptObj { daemon: daemon.clone(), path: path.clone(), action: std::sync::Mutex::new(Some(action)) };
        daemon.conn().object_server().at(path.as_str(), obj).await.map_err(SecretError::ZBus)?;
        Ok(op(&path))
    }

    async fn finish(daemon: Arc<Daemon>, path: String, dismissed: bool, result: OwnedVariant) {
        if let Ok(e) = SignalEmitter::new(daemon.conn(), path.clone()) {
            let _ = PromptObj::completed(&e, dismissed, result).await;
        }
        let _ = daemon.conn().object_server().remove::<PromptObj, _>(path.as_str()).await;
    }
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptObj {
    async fn prompt(&self, _window_id: &str) -> Result<(), SecretError> {
        let Some(action) = self.action.lock().unwrap().take() else {
            return Err(SecretError::Failed("the prompt was already used".into()));
        };
        let daemon = self.daemon.clone();
        let path = self.path.clone();
        // The reply must not wait for the user; the outcome goes out as the
        // Completed signal.
        tokio::spawn(async move {
            if !daemon.unlock_interactive().await {
                return PromptObj::finish(daemon, path, true, empty_variant()).await;
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
                    PromptObj::finish(daemon, path, true, empty_variant()).await
                }
            }
        });
        Ok(())
    }

    async fn dismiss(&self) -> Result<(), SecretError> {
        if self.action.lock().unwrap().take().is_some() {
            tokio::spawn(PromptObj::finish(self.daemon.clone(), self.path.clone(), true, empty_variant()));
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
    /// For login hooks and scripts. Failures are slowed down so that the
    /// method cannot be used to guess the password quickly.
    async fn unlock_with_password(&self, password: String) -> Result<(), SecretError> {
        let password = Zeroizing::new(password);
        match self.daemon.unlock_with_password(&password).await {
            Ok(()) => Ok(()),
            Err(e) => {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                Err(SecretError::Failed(e.to_string()))
            }
        }
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
    let _ = DEFAULT_ALIAS_PATH;
    daemon.sync_objects().await
}
