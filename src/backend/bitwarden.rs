//! Bitwarden backend: a root folder and its sub-folders hold the keyring.
//!
//! * Online: API-key login, `/sync`, writes straight to the server.
//! * Offline: the last sync response (still Bitwarden ciphertext) is cached,
//!   so the keyring unlocks and reads without a network; writes are queued
//!   and replayed in order on the next successful refresh.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::Mutex;

use super::{Backend, BackendError};
use crate::bw::api::{Api, ApiError, ApiKey, resolve_server_urls};
use crate::bw::crypto::{CryptoError, KdfParams, SymmetricKey, derive_master_key};
use crate::bw::items::{self, MapError};
use crate::config::{Config, Credentials, Paths};
use crate::fsutil::write_private;
use crate::model::{CollectionData, ItemData, LOGIN_COLLECTION, Snapshot, now, path_segment};

#[derive(Serialize, Deserialize)]
struct Cache {
    kdf: KdfParams,
    email: String,
    sync: Value,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum QueuedOp {
    /// `body` is already encrypted; `cipher_id` is None for a new item.
    Put {
        item_id: String,
        cipher_id: Option<String>,
        body: Map<String, Value>,
    },
    Trash {
        cipher_id: String,
    },
}

struct Unlocked {
    user_key: SymmetricKey,
    sync: Value,
    /// Bitwarden folder id → collection id.
    folders: BTreeMap<String, String>,
    /// Item id → cipher id.
    ciphers: HashMap<String, String>,
}

pub struct BitwardenBackend {
    email: String,
    root: String,
    api: Mutex<Api>,
    key: ApiKey,
    state: Mutex<Option<Unlocked>>,
    cache_path: PathBuf,
    queue_path: PathBuf,
    queue: Mutex<Vec<QueuedOp>>,
}

fn unavailable(e: impl std::fmt::Display) -> BackendError {
    BackendError::Unavailable(e.to_string())
}

fn map_api(e: ApiError) -> BackendError {
    if e.is_transient() { BackendError::Unavailable(e.to_string()) } else { BackendError::Rejected(e.to_string()) }
}

fn map_err(e: MapError) -> BackendError {
    BackendError::Rejected(e.to_string())
}

impl BitwardenBackend {
    pub fn new(config: &Config, creds: Credentials, paths: &Paths) -> anyhow::Result<Self> {
        let urls = resolve_server_urls(&config.server_url).map_err(anyhow::Error::msg)?;
        let device_path = paths.state.join("device-id");
        let device_id = match std::fs::read_to_string(&device_path) {
            Ok(s) if !s.trim().is_empty() => s.trim().to_owned(),
            _ => {
                let id = uuid::Uuid::new_v4().to_string();
                write_private(&device_path, id.as_bytes())?;
                id
            }
        };
        let queue_path = paths.state.join("queue.json");
        let queue = std::fs::read(&queue_path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Ok(BitwardenBackend {
            email: config.email.clone(),
            root: config.folder.trim_matches('/').to_owned(),
            api: Mutex::new(Api::new(urls, device_id)?),
            key: ApiKey { client_id: creds.client_id, client_secret: creds.client_secret },
            state: Mutex::new(None),
            cache_path: paths.cache.join("sync.json"),
            queue_path,
            queue: Mutex::new(queue),
        })
    }

    async fn ensure_login(&self) -> Result<(), ApiError> {
        let mut api = self.api.lock().await;
        if !api.is_logged_in() {
            api.login(&self.key).await?;
        }
        Ok(())
    }

    async fn fetch(&self) -> Result<Value, ApiError> {
        self.ensure_login().await?;
        self.api.lock().await.sync().await
    }

    fn save_cache(&self, kdf: KdfParams, sync: &Value) {
        let cache = Cache { kdf, email: self.email.clone(), sync: sync.clone() };
        if let Err(e) = write_private(&self.cache_path, &serde_json::to_vec(&cache).unwrap_or_default()) {
            tracing::warn!("could not write the offline cache: {e}");
        }
    }

    async fn save_queue(&self, queue: &[QueuedOp]) {
        if let Err(e) = write_private(&self.queue_path, &serde_json::to_vec(queue).unwrap_or_default()) {
            tracing::warn!("could not write the offline queue: {e}");
        }
    }

    /// Builds the keyring view of a sync response.
    fn snapshot(
        &self,
        sync: &Value,
        key: &SymmetricKey,
    ) -> (Snapshot, BTreeMap<String, String>, HashMap<String, String>) {
        let mut folders: BTreeMap<String, String> = BTreeMap::new();
        let mut collections = Vec::new();
        for f in sync.get("folders").and_then(Value::as_array).into_iter().flatten() {
            let (Some(id), Some(name)) = (f.get("id").and_then(Value::as_str), f.get("name").and_then(Value::as_str))
            else {
                continue;
            };
            let Ok(name) = key.decrypt_str(name) else { continue };
            let collection = if *name == self.root {
                LOGIN_COLLECTION.to_owned()
            } else if let Some(sub) =
                name.strip_prefix(&format!("{}/", self.root)).filter(|s| !s.is_empty() && !s.contains('/'))
            {
                let cid = path_segment(&sub.to_lowercase());
                collections.push(CollectionData { id: cid.clone(), label: sub.to_owned(), created: 0, modified: 0 });
                cid
            } else {
                continue;
            };
            // Duplicate folder names: the lowest id wins, so devices agree.
            match folders.iter().find(|(_, c)| **c == collection).map(|(fid, _)| fid.clone()) {
                Some(existing) if existing.as_str() < id => continue,
                Some(existing) => {
                    folders.remove(&existing);
                }
                None => {}
            }
            folders.insert(id.to_owned(), collection);
        }
        let mut items = Vec::new();
        let mut ciphers = HashMap::new();
        for c in sync.get("ciphers").and_then(Value::as_array).into_iter().flatten() {
            let Some(collection) = c.get("folderId").and_then(Value::as_str).and_then(|f| folders.get(f)) else {
                continue;
            };
            if !c.get("deletedDate").is_none_or(Value::is_null) || !c.get("organizationId").is_none_or(Value::is_null) {
                continue;
            }
            match items::decode(c, key, collection) {
                Ok(item) => {
                    if let Some(cid) = c.get("id").and_then(Value::as_str) {
                        // Two items claiming one id: keep the first, the later one is ignored.
                        if ciphers.contains_key(&item.id) {
                            continue;
                        }
                        ciphers.insert(item.id.clone(), cid.to_owned());
                    }
                    items.push(item);
                }
                Err(e) => tracing::debug!("skipping an item: {e}"),
            }
        }
        (Snapshot { collections, items }, folders, ciphers)
    }

    fn folder_for<'a>(state: &'a Unlocked, collection: &str) -> Option<&'a str> {
        state.folders.iter().find(|(_, c)| c.as_str() == collection).map(|(f, _)| f.as_str())
    }

    async fn ensure_folder(&self, collection: &str, label: &str) -> Result<String, BackendError> {
        {
            let state = self.state.lock().await;
            let state = state.as_ref().ok_or(BackendError::Locked)?;
            if let Some(f) = Self::folder_for(state, collection) {
                return Ok(f.to_owned());
            }
        }
        let name = if collection == LOGIN_COLLECTION { self.root.clone() } else { format!("{}/{label}", self.root) };
        let enc = {
            let state = self.state.lock().await;
            state.as_ref().ok_or(BackendError::Locked)?.user_key.encrypt_str(&name)
        };
        self.ensure_login().await.map_err(map_api)?;
        let folder = self.api.lock().await.create_folder(&enc).await.map_err(map_api)?;
        let id = folder.get("id").and_then(Value::as_str).ok_or_else(|| unavailable("folder without id"))?.to_owned();
        if let Some(s) = self.state.lock().await.as_mut() {
            s.folders.insert(id.clone(), collection.to_owned());
        }
        Ok(id)
    }

    fn cipher<'a>(state: &'a Unlocked, cipher_id: &str) -> Option<&'a Value> {
        state.sync.get("ciphers")?.as_array()?.iter().find(|c| c.get("id").and_then(Value::as_str) == Some(cipher_id))
    }

    /// Sends one write; returns the server's version of the item.
    async fn send(&self, op: &QueuedOp) -> Result<Option<Value>, ApiError> {
        self.ensure_login().await?;
        let api = self.api.lock().await;
        match op {
            QueuedOp::Put { cipher_id: Some(id), body, .. } => api.update_item(id, body.clone()).await.map(Some),
            QueuedOp::Put { cipher_id: None, body, .. } => api.create_item(body.clone()).await.map(Some),
            QueuedOp::Trash { cipher_id } => api.trash_item(cipher_id).await.map(|_| None),
        }
    }

    /// Records the server's answer in the cached sync so later edits build on it.
    async fn absorb(&self, item_id: Option<&str>, server: Option<Value>, trashed: Option<&str>) {
        let mut guard = self.state.lock().await;
        let Some(state) = guard.as_mut() else { return };
        let Some(list) = state.sync.get_mut("ciphers").and_then(Value::as_array_mut) else { return };
        if let Some(gone) = trashed {
            list.retain(|c| c.get("id").and_then(Value::as_str) != Some(gone));
            state.ciphers.retain(|_, cid| cid != gone);
        }
        if let Some(c) = server.map(crate::bw::api::normalize_keys) {
            let Some(cid) = c.get("id").and_then(Value::as_str).map(str::to_owned) else { return };
            list.retain(|x| x.get("id").and_then(Value::as_str) != Some(&cid));
            list.push(c);
            if let Some(id) = item_id {
                state.ciphers.insert(id.to_owned(), cid);
            }
        }
    }

    /// Replays queued writes. Stops at the first transient failure.
    async fn flush_queue(&self) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        while let Some(op) = queue.first().cloned() {
            let op = match op {
                // A create queued while offline may have become an update
                // because an earlier queued create of the same item went through.
                QueuedOp::Put { item_id, cipher_id: None, body } => {
                    let known = self.state.lock().await.as_ref().and_then(|s| s.ciphers.get(&item_id).cloned());
                    QueuedOp::Put { item_id, cipher_id: known, body }
                }
                other => other,
            };
            match self.send(&op).await {
                Ok(server) => {
                    match &op {
                        QueuedOp::Put { item_id, .. } => self.absorb(Some(item_id), server, None).await,
                        QueuedOp::Trash { cipher_id } => self.absorb(None, None, Some(cipher_id)).await,
                    }
                    queue.remove(0);
                    self.save_queue(&queue).await;
                }
                Err(e) if e.is_transient() => return Err(map_api(e)),
                Err(e) if e.is_out_of_date() => {
                    // Last writer wins, like the macOS keychain: re-base on the current revision.
                    tracing::info!("a queued edit raced with another device; it is re-applied on the next refresh");
                    queue.remove(0);
                    self.save_queue(&queue).await;
                }
                Err(e) => {
                    tracing::warn!("dropping a queued write the server rejected: {e}");
                    queue.remove(0);
                    self.save_queue(&queue).await;
                }
            }
        }
        Ok(())
    }

    async fn write(&self, op: QueuedOp) -> Result<(), BackendError> {
        // Keep order: while anything is queued, new writes queue behind it.
        let pending = !self.queue.lock().await.is_empty();
        if !pending {
            match self.send(&op).await {
                Ok(server) => {
                    match &op {
                        QueuedOp::Put { item_id, .. } => self.absorb(Some(item_id), server, None).await,
                        QueuedOp::Trash { cipher_id } => self.absorb(None, None, Some(cipher_id)).await,
                    }
                    return Ok(());
                }
                Err(e) if !e.is_transient() => return Err(map_api(e)),
                Err(e) => tracing::info!("offline ({e}); the change is queued"),
            }
        }
        let mut queue = self.queue.lock().await;
        queue.push(op);
        self.save_queue(&queue).await;
        Ok(())
    }

    async fn put_once(&self, item: &ItemData) -> Result<(), BackendError> {
        let label = item.collection.clone();
        let folder = match self.ensure_folder(&item.collection, &label).await {
            Ok(f) => f,
            Err(BackendError::Unavailable(e)) => {
                return Err(BackendError::Unavailable(format!("cannot create the collection folder offline: {e}")));
            }
            Err(e) => return Err(e),
        };
        let op = {
            let guard = self.state.lock().await;
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            let cipher_id = state.ciphers.get(&item.id).cloned();
            let existing = cipher_id.as_deref().and_then(|c| Self::cipher(state, c));
            let body = items::encode(item, existing, &state.user_key, &folder).map_err(map_err)?;
            QueuedOp::Put { item_id: item.id.clone(), cipher_id, body }
        };
        self.write(op).await
    }
}

#[async_trait]
impl Backend for BitwardenBackend {
    async fn unlock(&self, password: &str) -> Result<Snapshot, BackendError> {
        let online: Result<(KdfParams, Value), ApiError> = async {
            let kdf = self.api.lock().await.prelogin(&self.email).await?;
            let sync = self.fetch().await?;
            Ok((kdf, sync))
        }
        .await;
        let (kdf, sync, from_cache) = match online {
            Ok((kdf, sync)) => (kdf, sync, false),
            Err(e) if e.is_transient() => {
                let cache: Cache = std::fs::read(&self.cache_path)
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .filter(|c: &Cache| c.email == self.email)
                    .ok_or_else(|| {
                        unavailable(format!("Bitwarden is unreachable and there is no offline copy yet: {e}"))
                    })?;
                tracing::info!("Bitwarden unreachable; unlocking from the offline copy");
                (cache.kdf, cache.sync, true)
            }
            Err(e) => return Err(map_api(e)),
        };
        let protected = sync
            .pointer("/profile/key")
            .and_then(Value::as_str)
            .ok_or_else(|| unavailable("sync without account key"))?;
        let master =
            derive_master_key(password, &self.email, kdf).map_err(|e| BackendError::Rejected(e.to_string()))?;
        let stretched = SymmetricKey::stretch(&master);
        let user_key = match stretched.decrypt_key(protected) {
            Ok(k) => k,
            Err(CryptoError::BadMac) => return Err(BackendError::WrongPassword),
            Err(e) => return Err(BackendError::Rejected(e.to_string())),
        };
        if !from_cache {
            self.save_cache(kdf, &sync);
        }
        let (snap, folders, ciphers) = self.snapshot(&sync, &user_key);
        *self.state.lock().await = Some(Unlocked { user_key, sync, folders, ciphers });
        if !from_cache && let Err(e) = self.flush_queue().await {
            tracing::info!("queued changes stay queued: {e}");
        }
        Ok(snap)
    }

    async fn lock(&self) {
        *self.state.lock().await = None;
        self.api.lock().await.logout();
    }

    async fn refresh(&self) -> Result<Option<Snapshot>, BackendError> {
        if self.state.lock().await.is_none() {
            return Err(BackendError::Locked);
        }
        self.flush_queue().await?;
        let sync = self.fetch().await.map_err(map_api)?;
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        let changed =
            sync.get("ciphers") != state.sync.get("ciphers") || sync.get("folders") != state.sync.get("folders");
        if !changed {
            return Ok(None);
        }
        let (snap, folders, ciphers) = self.snapshot(&sync, &state.user_key);
        state.sync = sync;
        state.folders = folders;
        state.ciphers = ciphers;
        let kdf =
            std::fs::read(&self.cache_path).ok().and_then(|b| serde_json::from_slice::<Cache>(&b).ok()).map(|c| c.kdf);
        if let Some(kdf) = kdf {
            self.save_cache(kdf, &state.sync);
        }
        Ok(Some(snap))
    }

    async fn create_collection(&self, label: &str) -> Result<CollectionData, BackendError> {
        let label = label.trim().replace('/', "-");
        if label.is_empty() {
            return Err(BackendError::Rejected("a collection needs a label".into()));
        }
        let id = path_segment(&label.to_lowercase());
        self.ensure_folder(&id, &label).await?;
        Ok(CollectionData { id, label, created: now(), modified: now() })
    }

    async fn delete_collection(&self, id: &str) -> Result<(), BackendError> {
        let (folder, item_ciphers) = {
            let guard = self.state.lock().await;
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            let Some(folder) = Self::folder_for(state, id).map(str::to_owned) else { return Ok(()) };
            let ciphers: Vec<String> = state
                .sync
                .get("ciphers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|c| c.get("folderId").and_then(Value::as_str) == Some(folder.as_str()))
                .filter_map(|c| c.get("id").and_then(Value::as_str).map(str::to_owned))
                .collect();
            (folder, ciphers)
        };
        for cipher_id in item_ciphers {
            self.write(QueuedOp::Trash { cipher_id }).await?;
        }
        self.ensure_login().await.map_err(map_api)?;
        self.api.lock().await.delete_folder(&folder).await.map_err(map_api)?;
        if let Some(s) = self.state.lock().await.as_mut() {
            s.folders.remove(&folder);
        }
        Ok(())
    }

    async fn put_item(&self, item: &ItemData) -> Result<(), BackendError> {
        match self.put_once(item).await {
            Err(BackendError::Rejected(msg)) if msg.to_lowercase().contains("out of date") => {
                // Another device changed the item: take its revision, re-apply ours.
                if let Ok(Some(_)) = self.refresh().await {}
                self.put_once(item).await
            }
            other => other,
        }
    }

    async fn delete_item(&self, item: &ItemData) -> Result<(), BackendError> {
        let cipher_id = {
            let guard = self.state.lock().await;
            guard.as_ref().ok_or(BackendError::Locked)?.ciphers.get(&item.id).cloned()
        };
        match cipher_id {
            Some(cipher_id) => self.write(QueuedOp::Trash { cipher_id }).await,
            None => {
                // Never reached the server: drop it from the queue.
                let mut queue = self.queue.lock().await;
                queue.retain(|op| !matches!(op, QueuedOp::Put { item_id, .. } if *item_id == item.id));
                self.save_queue(&queue).await;
                Ok(())
            }
        }
    }

    async fn describe(&self) -> String {
        let queued = self.queue.lock().await.len();
        let urls = self.api.lock().await.urls().clone();
        format!("Bitwarden {} ({}), folder \"{}\", {queued} queued change(s)", self.email, urls.identity, self.root)
    }
}
