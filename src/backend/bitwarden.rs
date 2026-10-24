//! Bitwarden backend: the keyring is every vault item marked with `bwss:id`
//! (design §3, §8).
//!
//! * Online: API-key login, `/sync`, writes straight to the server.
//! * Offline: the last sync response (still Bitwarden ciphertext) is cached,
//!   so the keyring unlocks and reads without a network; writes are queued,
//!   shown at once, and replayed in order on the next successful refresh.
//!
//! The read path follows the marker model. The write path is an interim one
//! (new items go to the keyring folder through `items::encode`) until the
//! marker write path replaces it.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;

use super::ops::{Loaded, Op, read_versioned, seal, set_aside, unseal};
use super::registry::{REGISTRY_ID, Registry};
use super::{Backend, BackendError};
use crate::bw::api::{Api, ApiError, ApiKey, resolve_server_urls};
use crate::bw::crypto::{CryptoError, KdfParams, SymmetricKey, derive_master_key};
use crate::bw::fields::{A_NAME, F_KIND, field_names, field_value, first_index};
use crate::bw::items::{self, item_key};
use crate::bw::scan::{Keys, MarkedItem, Scan, ValueSource, normalize_collection, resolve_duplicates, scan};
use crate::bw::write::{apply, new_note};
use crate::config::{Config, Credentials, Paths};
use crate::fsutil::write_private;
use crate::model::{CollectionData, ItemData, LOGIN_COLLECTION, SESSION_COLLECTION, Snapshot};

const FORMAT: u64 = 2;
const TYPE_SECURE_NOTE: u64 = 2;
/// `bwss:kind` of the collection registry note.
const KIND_COLLECTIONS: &str = "collections";
/// Cipher id of an item created by a queued op: it is not on the server yet.
const QUEUED: &str = "";

/// `sync.json`: the last `/sync` response, still ciphertext.
#[derive(Serialize, Deserialize)]
struct Cache {
    format: u64,
    kdf: KdfParams,
    email: String,
    /// Raw `/accounts/revision-date` answer at the time of the sync.
    #[serde(default)]
    revision: Option<String>,
    sync: Value,
}

/// The keyring as read from one copy of the vault.
pub(crate) struct Built {
    pub snapshot: Snapshot,
    /// Marked items by `bwss:id`, duplicates resolved, registry excluded.
    pub marked: HashMap<String, MarkedItem>,
    /// Union of every registry note.
    pub registry: Registry,
    /// Cipher ids of the registry notes.
    pub registry_ciphers: Vec<String>,
    /// A registry note could not be read: it must never be written over.
    #[allow(dead_code)] // Task 11 refuses registry writes on it.
    pub registry_unreadable: bool,
    /// `(bwss:id, losing cipher ids)`.
    #[allow(dead_code)] // Task 11 lists them in `bwss status`.
    pub duplicates: Vec<(String, Vec<String>)>,
    /// `(cipher id, reason)` of marked items that are not supported.
    #[allow(dead_code)] // Task 11 lists them in `bwss status`.
    pub skipped: Vec<(String, String)>,
    /// Scan cache: `(cipher id, raw revisionDate)` of unmarked ciphers.
    pub unmarked: HashSet<(String, String)>,
}

/// Scan-cache key of a cipher; `None` when it has no revision to compare.
fn cache_key(cipher: &Value) -> Option<(String, String)> {
    let id = cipher.get("id").and_then(Value::as_str).filter(|id| !id.is_empty())?;
    let rev = cipher.get("revisionDate").filter(|r| !r.is_null())?;
    Some((id.to_owned(), rev.to_string()))
}

fn ciphers(sync: &Value) -> &[Value] {
    sync.get("ciphers").and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// A marked item with the registry id: `Ok(Some)` for a registry note,
/// `Ok(None)` for anything else, `Err` when its notes cannot be read.
fn read_registry(cipher: &Value, keys: &Keys) -> Result<Option<Registry>, ()> {
    if cipher.get("type").and_then(Value::as_u64) != Some(TYPE_SECURE_NOTE) {
        return Ok(None);
    }
    let key = item_key(cipher, &keys.user).map_err(|_| ())?;
    let names = field_names(cipher, &key).map_err(|_| ())?;
    let Some(i) = first_index(&names, F_KIND) else { return Ok(None) };
    if field_value(cipher, i, &key).map_err(|_| ())?.trim() != KIND_COLLECTIONS {
        return Ok(None);
    }
    let notes = match cipher.get("notes").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => key.decrypt_str(s).map_err(|_| ())?,
        _ => return Ok(Some(Registry::default())),
    };
    if notes.trim().is_empty() {
        return Ok(Some(Registry::default()));
    }
    Registry::try_parse(&notes).map(Some).map_err(|_| ())
}

/// Builds the keyring from a copy of the vault (design §8.2 step 4).
///
/// `previous` supplies the scan cache (unchanged unmarked ciphers are not
/// decrypted again) and the items to hold: a marked item whose cipher can
/// no longer be inspected stays as last read (§3.4).
pub(crate) fn build(sync: &Value, keys: &Keys, previous: Option<&Built>) -> Built {
    let held: HashMap<&str, &MarkedItem> =
        previous.map(|p| p.marked.values().map(|m| (m.cipher_id.as_str(), m)).collect()).unwrap_or_default();
    let mut found = Vec::new();
    let mut unmarked = HashSet::new();
    let mut skipped = Vec::new();
    let mut registry = Registry::default();
    let mut registry_ciphers = Vec::new();
    let mut registry_unreadable = false;

    for cipher in ciphers(sync) {
        let cid = cipher.get("id").and_then(Value::as_str).unwrap_or_default();
        let key = cache_key(cipher);
        if let (Some(p), Some(k)) = (previous, &key)
            && p.unmarked.contains(k)
        {
            unmarked.insert(k.clone());
            continue;
        }
        match scan(cipher, keys) {
            Scan::Unmarked => unmarked.extend(key),
            Scan::Marked(m) if m.item.id == REGISTRY_ID => match read_registry(cipher, keys) {
                Ok(Some(r)) => {
                    registry.merge(&r);
                    registry_ciphers.push(cid.to_owned());
                }
                Ok(None) => {
                    tracing::warn!(cipher = cid, "{REGISTRY_ID} is reserved for the collection registry; skipped");
                    skipped.push((cid.to_owned(), format!("{cid}: {REGISTRY_ID} is reserved")));
                }
                Err(()) => {
                    tracing::warn!(cipher = cid, "the collection registry cannot be read");
                    registry_unreadable = true;
                    registry_ciphers.push(cid.to_owned());
                }
            },
            Scan::Marked(m) => found.push(*m),
            Scan::Uninspectable(why) => {
                tracing::warn!("{why}");
                if cid.is_empty() {
                    continue;
                }
                if let Some(m) = held.get(cid) {
                    found.push((*m).clone());
                }
                if let Some(p) = previous.filter(|p| p.registry_ciphers.iter().any(|c| c == cid)) {
                    registry.merge(&p.registry);
                    registry_unreadable = true;
                    registry_ciphers.push(cid.to_owned());
                }
            }
            Scan::Skipped(why) => {
                tracing::warn!("{why}");
                skipped.push((cid.to_owned(), why));
            }
        }
    }

    let (winners, duplicates) = resolve_duplicates(found);
    for (id, losers) in &duplicates {
        tracing::warn!(id = %id, losers = ?losers, "several items carry one bwss:id; the oldest is used");
    }

    let mut collections: BTreeMap<String, CollectionData> = BTreeMap::new();
    collections.insert(
        LOGIN_COLLECTION.into(),
        CollectionData { id: LOGIN_COLLECTION.into(), label: "Login".into(), created: 0, modified: 0 },
    );
    for (id, entry) in registry.live() {
        let id = normalize_collection(id);
        if id == LOGIN_COLLECTION || id == SESSION_COLLECTION {
            continue;
        }
        collections.insert(
            id.clone(),
            CollectionData { id, label: entry.label.clone(), created: entry.created, modified: entry.created },
        );
    }
    let mut items: Vec<ItemData> = winners.iter().map(|m| m.item.clone()).collect();
    items.sort_by(|a, b| a.id.cmp(&b.id));
    for item in &items {
        collections.entry(item.collection.clone()).or_insert_with(|| CollectionData {
            id: item.collection.clone(),
            label: item.collection.clone(),
            created: 0,
            modified: 0,
        });
    }

    Built {
        snapshot: Snapshot { collections: collections.into_values().collect(), items },
        marked: winners.into_iter().map(|m| (m.item.id.clone(), m)).collect(),
        registry,
        registry_ciphers,
        registry_unreadable,
        duplicates,
        skipped,
        unmarked,
    }
}

/// Index in `list` of the cipher that holds `id` on the server.
fn find_marked(list: &[Value], id: &str, keys: &Keys, unmarked: &HashSet<(String, String)>) -> Option<usize> {
    let mut found = Vec::new();
    for c in list {
        if cache_key(c).is_some_and(|k| unmarked.contains(&k)) {
            continue;
        }
        if let Scan::Marked(m) = scan(c, keys)
            && m.item.id == id
        {
            found.push(*m);
        }
    }
    let (winners, _) = resolve_duplicates(found);
    let cid = winners.into_iter().next().map(|m| m.cipher_id).filter(|c| c != QUEUED)?;
    list.iter().position(|c| c.get("id").and_then(Value::as_str) == Some(&cid))
}

/// The cache with every queued op applied, so pending writes stay visible
/// (design §8.2 step 3).
fn with_queue(
    sync: &Value,
    queue: &[Op],
    keys: &Keys,
    folder: Option<&str>,
    unmarked: &HashSet<(String, String)>,
) -> Value {
    let mut view = sync.clone();
    let Some(list) = view.get_mut("ciphers").and_then(Value::as_array_mut) else { return view };
    for op in queue {
        match op {
            Op::Create { item, .. } => match new_note(item, folder, keys) {
                Ok(mut body) => {
                    body.insert("id".into(), json!(QUEUED));
                    list.push(Value::Object(body));
                }
                Err(e) => tracing::warn!("a queued new item cannot be shown: {e}"),
            },
            Op::Patch(patch) => {
                let Some(i) = find_marked(list, &patch.id, keys, unmarked) else { continue };
                match apply(&list[i], patch, keys) {
                    Ok(mut body) => {
                        body.remove("lastKnownRevisionDate");
                        for k in ["id", "revisionDate", "creationDate"] {
                            if let Some(v) = list[i].get(k) {
                                body.insert(k.into(), v.clone());
                            }
                        }
                        list[i] = Value::Object(body);
                    }
                    Err(e) => tracing::warn!("a queued change cannot be shown: {e}"),
                }
            }
            Op::Delete { id, .. } => {
                if let Some(i) = find_marked(list, id, keys, unmarked) {
                    list.remove(i);
                }
            }
            // Collections are not written yet.
            Op::Registry { .. } => {}
        }
    }
    view
}

/// Builds the keyring for a freshly loaded cache and queue.
fn build_fresh(sync: &Value, queue: &[Op], keys: &Keys, folder: Option<&str>) -> Built {
    let base = build(sync, keys, None);
    if queue.is_empty() {
        return base;
    }
    let view = with_queue(sync, queue, keys, folder, &base.unmarked);
    build(&view, keys, Some(&base))
}

/// Whether the interim legacy update `body` of `cipher` changes only what
/// `item` asks for: the item keeps its id, collection, label and name, and a
/// login keeps its notes. `items::encode` drops the marker model's own
/// fields, so anything else is refused until the marker write path lands.
fn encode_keeps_item(cipher: &Value, body: &Map<String, Value>, item: &ItemData, keys: &Keys) -> bool {
    if cipher.get("type").and_then(Value::as_u64) == Some(1) && body.get("notes") != cipher.get("notes") {
        return false;
    }
    let mut after = body.clone();
    for k in ["id", "revisionDate", "creationDate"] {
        if let Some(v) = cipher.get(k) {
            after.insert(k.into(), v.clone());
        }
    }
    let name = |m: &MarkedItem| m.item.attributes.get(A_NAME).cloned();
    match (scan(cipher, keys), scan(&Value::Object(after), keys)) {
        (Scan::Marked(old), Scan::Marked(new)) => {
            new.item.id == item.id
                && new.item.collection == item.collection
                && new.item.label == item.label
                && name(&new) == name(&old)
        }
        _ => false,
    }
}

/// Id of the keyring folder: the folder named `name`, lowest id first.
fn keyring_folder(sync: &Value, key: &SymmetricKey, name: &str) -> Option<String> {
    sync.get("folders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|f| {
            let id = f.get("id").and_then(Value::as_str)?;
            let enc = f.get("name").and_then(Value::as_str)?;
            (key.decrypt_str(enc).ok()?.as_str() == name).then(|| id.to_owned())
        })
        .min()
}

/// Reads `sync.json`. `Ok(None)` when there is no usable copy; an error when
/// the file exists but cannot be read (it is then left alone).
fn load_cache(path: &Path, email: &str) -> Result<Option<Cache>, BackendError> {
    match read_versioned(path, "legacy") {
        Loaded::Ok(v) => Ok(serde_json::from_value::<Cache>(v).ok().filter(|c| c.email == email)),
        Loaded::Missing | Loaded::SetAside(_) => Ok(None),
        Loaded::Unreadable(e) => {
            Err(unavailable(format!("cannot read the offline copy {}: {e}; it is left untouched", path.display())))
        }
    }
}

/// Reads `queue.json`, sealed with the user key.
fn load_queue(path: &Path, key: &SymmetricKey) -> Result<Vec<Op>, BackendError> {
    let refuse = |e: std::io::Error| {
        unavailable(format!("cannot read the write queue {}: {e}; it is left untouched", path.display()))
    };
    match read_versioned(path, "legacy") {
        Loaded::Ok(v) => match unseal(&v, key) {
            Ok(ops) => Ok(ops),
            Err(e) => {
                tracing::warn!(path = %path.display(), "the write queue cannot be opened ({e}); setting it aside");
                match set_aside(path, "unsealable") {
                    Loaded::Unreadable(e) => Err(refuse(e)),
                    _ => Ok(Vec::new()),
                }
            }
        },
        Loaded::Missing => Ok(Vec::new()),
        Loaded::SetAside(to) => {
            tracing::warn!(moved_to = %to.display(), "changes queued by an older version are not replayed");
            Ok(Vec::new())
        }
        Loaded::Unreadable(e) => Err(refuse(e)),
    }
}

struct Unlocked {
    keys: Keys,
    kdf: KdfParams,
    /// The server's copy of the vault, as cached; queued ops are not in it.
    sync: Value,
    /// Raw account revision date of `sync`, when known.
    revision: Option<String>,
    /// The keyring: `sync` with the queue applied.
    built: Built,
    keyring_folder: Option<String>,
}

pub struct BitwardenBackend {
    email: String,
    root: String,
    api: Mutex<Api>,
    key: ApiKey,
    state: Mutex<Option<Unlocked>>,
    cache_path: PathBuf,
    queue_path: PathBuf,
    /// Queued ops; loaded at unlock (it is sealed with the user key) and
    /// dropped at lock. Lock order: `queue`, then `state`.
    queue: Mutex<Vec<Op>>,
}

fn unavailable(e: impl std::fmt::Display) -> BackendError {
    BackendError::Unavailable(e.to_string())
}

fn map_api(e: ApiError) -> BackendError {
    if e.is_transient() { BackendError::Unavailable(e.to_string()) } else { BackendError::Rejected(e.to_string()) }
}

/// What a queued op needs from the server.
enum Outgoing {
    Create(Map<String, Value>),
    Update(String, Map<String, Value>),
    Trash(String),
    Drop(String),
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
        Ok(BitwardenBackend {
            email: config.email.clone(),
            root: config.folder.trim_matches('/').to_owned(),
            api: Mutex::new(Api::new(urls, device_id)?),
            key: ApiKey { client_id: creds.client_id, client_secret: creds.client_secret },
            state: Mutex::new(None),
            cache_path: paths.cache.join("sync.json"),
            queue_path: paths.state.join("queue.json"),
            queue: Mutex::new(Vec::new()),
        })
    }

    async fn ensure_login(&self) -> Result<(), ApiError> {
        let mut api = self.api.lock().await;
        if !api.is_logged_in() {
            api.login(&self.key).await?;
        }
        Ok(())
    }

    /// `/accounts/revision-date` (when it answers), then `/sync`.
    async fn fetch(&self) -> Result<(Option<String>, Value), ApiError> {
        self.ensure_login().await?;
        let mut api = self.api.lock().await;
        let revision = api.revision_date().await.ok();
        Ok((revision, api.sync().await?))
    }

    /// Whether writes can go to the server now: logged in and synced.
    async fn can_write(&self) -> bool {
        self.ensure_login().await.is_ok() && self.api.lock().await.has_profile()
    }

    fn save_cache(&self, state: &Unlocked) {
        let cache = Cache {
            format: FORMAT,
            kdf: state.kdf,
            email: self.email.clone(),
            revision: state.revision.clone(),
            sync: state.sync.clone(),
        };
        if let Err(e) = write_private(&self.cache_path, &serde_json::to_vec(&cache).unwrap_or_default()) {
            tracing::warn!("could not write the offline cache: {e}");
        }
    }

    fn save_queue(&self, queue: &[Op], key: &SymmetricKey) {
        if let Err(e) = write_private(&self.queue_path, &serde_json::to_vec(&seal(queue, key)).unwrap_or_default()) {
            tracing::warn!("could not write the offline queue: {e}");
        }
    }

    /// Rebuilds the keyring after the cache or the queue changed.
    fn rebuild(state: &mut Unlocked, queue: &[Op]) {
        let view = if queue.is_empty() {
            Cow::Borrowed(&state.sync)
        } else {
            Cow::Owned(with_queue(
                &state.sync,
                queue,
                &state.keys,
                state.keyring_folder.as_deref(),
                &state.built.unmarked,
            ))
        };
        state.built = build(&view, &state.keys, Some(&state.built));
    }

    /// Records the server's answer in the cache, so later edits build on it.
    fn absorb(&self, state: &mut Unlocked, queue: &[Op], server: Option<Value>, trashed: Option<&str>) {
        if let Some(list) = state.sync.get_mut("ciphers").and_then(Value::as_array_mut) {
            if let Some(gone) = trashed {
                list.retain(|c| c.get("id").and_then(Value::as_str) != Some(gone));
            }
            if let Some(c) = server.map(crate::bw::api::normalize_keys)
                && let Some(cid) = c.get("id").and_then(Value::as_str).map(str::to_owned)
            {
                list.retain(|x| x.get("id").and_then(Value::as_str) != Some(&cid));
                list.push(c);
            }
        }
        // Keep the offline copy current, so that what was written is still
        // there when the next unlock happens without a network.
        self.save_cache(state);
        Self::rebuild(state, queue);
    }

    /// Queues `op` behind the others, keeps it on disk and shows it.
    async fn enqueue(&self, queue: &mut Vec<Op>, op: Op) -> Result<(), BackendError> {
        queue.push(op);
        self.queue_changed(queue).await
    }

    async fn queue_changed(&self, queue: &[Op]) -> Result<(), BackendError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        self.save_queue(queue, &state.keys.user);
        Self::rebuild(state, queue);
        Ok(())
    }

    async fn ensure_keyring_folder(&self) -> Result<String, BackendError> {
        let enc = {
            let state = self.state.lock().await;
            let state = state.as_ref().ok_or(BackendError::Locked)?;
            if let Some(f) = &state.keyring_folder {
                return Ok(f.clone());
            }
            state.keys.user.encrypt_str(&self.root)
        };
        self.ensure_login().await.map_err(map_api)?;
        let folder = self.api.lock().await.create_folder(&enc).await.map_err(map_api)?;
        let id = folder.get("id").and_then(Value::as_str).ok_or_else(|| unavailable("folder without id"))?.to_owned();
        if let Some(s) = self.state.lock().await.as_mut() {
            s.keyring_folder = Some(id.clone());
        }
        Ok(id)
    }

    /// Works out what the first queued op needs from the server.
    async fn prepare(&self, op: &Op) -> Result<Outgoing, BackendError> {
        let folder = match op {
            Op::Create { .. } => Some(self.ensure_keyring_folder().await?),
            _ => None,
        };
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;
        let list = ciphers(&state.sync);
        let find = |id: &str| find_marked(list, id, &state.keys, &state.built.unmarked);
        Ok(match op {
            Op::Create { item, .. } => match new_note(item, folder.as_deref(), &state.keys) {
                Ok(body) => Outgoing::Create(body),
                Err(e) => Outgoing::Drop(format!("a queued new item cannot be written: {e}")),
            },
            Op::Patch(patch) => match find(&patch.id) {
                None => Outgoing::Drop("a queued change targets an item that is gone".into()),
                Some(i) => match apply(&list[i], patch, &state.keys) {
                    Ok(body) => {
                        let cid = list[i].get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
                        Outgoing::Update(cid, body)
                    }
                    Err(crate::bw::write::WriteError::Uninspectable(why)) => {
                        return Err(unavailable(format!("a queued change waits: {why}")));
                    }
                    Err(e) => Outgoing::Drop(format!("a queued change cannot be applied: {e}")),
                },
            },
            Op::Delete { id, .. } => match find(id) {
                None => Outgoing::Drop("a queued delete targets an item that is gone".into()),
                Some(i) => Outgoing::Trash(list[i].get("id").and_then(Value::as_str).unwrap_or_default().to_owned()),
            },
            Op::Registry { .. } => {
                return Err(BackendError::Rejected("a queued collection change waits: not supported yet".into()));
            }
        })
    }

    /// Replays queued writes in order. Stops at the first transient failure.
    async fn flush_queue(&self) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        let result = self.flush_locked(&mut queue).await;
        if matches!(result, Err(BackendError::Locked)) {
            // Locked meanwhile: queued secrets leave memory with the keys.
            queue.clear();
        }
        result
    }

    async fn flush_locked(&self, queue: &mut Vec<Op>) -> Result<(), BackendError> {
        if queue.is_empty() || !self.can_write().await {
            return Ok(());
        }
        while let Some(op) = queue.first() {
            let step = self.prepare(op).await?;
            let sent = {
                let api = self.api.lock().await;
                match &step {
                    Outgoing::Create(body) => api.create_item(body.clone()).await.map(Some),
                    Outgoing::Update(cid, body) => api.update_item(cid, body.clone()).await.map(Some),
                    Outgoing::Trash(cid) => api.trash_item(cid).await.map(|()| None),
                    Outgoing::Drop(why) => {
                        tracing::warn!("dropping a queued write: {why}");
                        Ok(None)
                    }
                }
            };
            let (server, trashed) = match (&step, sent) {
                (_, Err(e)) if e.is_transient() => return Err(map_api(e)),
                (_, Err(e)) => {
                    tracing::warn!("dropping a queued write the server rejected: {e}");
                    (None, None)
                }
                (Outgoing::Trash(cid), Ok(_)) => (None, Some(cid.as_str())),
                (_, Ok(server)) => (server, None),
            };
            queue.remove(0);
            let mut guard = self.state.lock().await;
            let state = guard.as_mut().ok_or(BackendError::Locked)?;
            self.save_queue(queue, &state.keys.user);
            self.absorb(state, queue, server, trashed);
        }
        Ok(())
    }

    async fn put_once(&self, item: &ItemData) -> Result<(), BackendError> {
        // `items::encode` would store binary as base64 in a value bwss does
        // not own, which the marker read path refuses (design §3.2).
        if std::str::from_utf8(&item.secret).is_err() {
            return Err(BackendError::Rejected("binary secrets are not supported yet".into()));
        }
        let mut queue = self.queue.lock().await;
        let target = {
            let guard = self.state.lock().await;
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            state.built.marked.get(&item.id).map(|m| (m.cipher_id.clone(), m.source))
        };
        match target {
            // Not on the server yet: the queued create carries the new version.
            Some((cid, _)) if cid == QUEUED => {
                for op in queue.iter_mut() {
                    if let Op::Create { id, collection, item: queued } = op
                        && *id == item.id
                    {
                        *collection = item.collection.clone();
                        *queued = item.clone();
                    }
                }
                self.queue_changed(&queue).await
            }
            // `items::encode` writes the login password or the note text; a
            // value kept elsewhere would be left behind and another one
            // overwritten.
            Some((_, ValueSource::Field | ValueSource::BwssNotes)) => {
                Err(BackendError::Rejected("changing this item is not supported yet".into()))
            }
            Some((cid, _)) => {
                // Keep order: while anything is queued, nothing jumps ahead.
                if !queue.is_empty() || !self.can_write().await {
                    return Err(unavailable("offline: changes to existing items cannot be queued yet"));
                }
                let body = {
                    let guard = self.state.lock().await;
                    let state = guard.as_ref().ok_or(BackendError::Locked)?;
                    let cipher = ciphers(&state.sync)
                        .iter()
                        .find(|c| c.get("id").and_then(Value::as_str) == Some(&cid))
                        .ok_or_else(|| unavailable("the item is not in the cache"))?;
                    let mut body = items::encode(item, Some(cipher), &state.keys.user, "")
                        .map_err(|e| BackendError::Rejected(e.to_string()))?;
                    // The item stays in its own folder.
                    body.insert("folderId".into(), cipher.get("folderId").cloned().unwrap_or(Value::Null));
                    if !encode_keeps_item(cipher, &body, item, &state.keys) {
                        return Err(BackendError::Rejected("changing this item is not supported yet".into()));
                    }
                    body
                };
                let server = self.api.lock().await.update_item(&cid, body).await;
                match server {
                    Ok(server) => {
                        let mut guard = self.state.lock().await;
                        let state = guard.as_mut().ok_or(BackendError::Locked)?;
                        self.absorb(state, &queue, Some(server), None);
                        Ok(())
                    }
                    Err(e) if e.is_transient() => {
                        Err(unavailable(format!("offline ({e}): changes to existing items cannot be queued yet")))
                    }
                    Err(e) => Err(map_api(e)),
                }
            }
            None => {
                let create =
                    Op::Create { id: item.id.clone(), collection: item.collection.clone(), item: item.clone() };
                if !queue.is_empty() || !self.can_write().await {
                    return self.enqueue(&mut queue, create).await;
                }
                let folder = match self.ensure_keyring_folder().await {
                    Ok(f) => f,
                    Err(BackendError::Unavailable(e)) => {
                        tracing::info!("offline ({e}); the new item is queued");
                        return self.enqueue(&mut queue, create).await;
                    }
                    Err(e) => return Err(e),
                };
                let body = {
                    let guard = self.state.lock().await;
                    let state = guard.as_ref().ok_or(BackendError::Locked)?;
                    items::encode(item, None, &state.keys.user, &folder)
                        .map_err(|e| BackendError::Rejected(e.to_string()))?
                };
                let server = self.api.lock().await.create_item(body).await;
                match server {
                    Ok(server) => {
                        let mut guard = self.state.lock().await;
                        let state = guard.as_mut().ok_or(BackendError::Locked)?;
                        self.absorb(state, &queue, Some(server), None);
                        Ok(())
                    }
                    Err(e) if e.is_transient() => {
                        tracing::info!("offline ({e}); the new item is queued");
                        self.enqueue(&mut queue, create).await
                    }
                    Err(e) => Err(map_api(e)),
                }
            }
        }
    }
}

#[async_trait]
impl Backend for BitwardenBackend {
    async fn unlock(&self, password: &str) -> Result<Snapshot, BackendError> {
        let online: Result<(KdfParams, Option<String>, Value), ApiError> = async {
            let kdf = self.api.lock().await.prelogin(&self.email).await?;
            let (revision, sync) = self.fetch().await?;
            Ok((kdf, revision, sync))
        }
        .await;
        let (kdf, revision, sync, from_cache) = match online {
            Ok((kdf, revision, sync)) => (kdf, revision, sync, false),
            Err(e) if e.is_transient() => {
                let cache = load_cache(&self.cache_path, &self.email)?.ok_or_else(|| {
                    unavailable(format!("Bitwarden is unreachable and there is no offline copy yet: {e}"))
                })?;
                tracing::info!("Bitwarden unreachable; unlocking from the offline copy");
                (cache.kdf, cache.revision, cache.sync, true)
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
        let user = match stretched.decrypt_key(protected) {
            Ok(k) => k,
            Err(CryptoError::BadMac) => return Err(BackendError::WrongPassword),
            Err(e) => return Err(BackendError::Rejected(e.to_string())),
        };
        let keys = Keys { mark: user.derive("value-mark"), user };

        let mut queue = self.queue.lock().await;
        *queue = load_queue(&self.queue_path, &keys.user)?;
        let folder = keyring_folder(&sync, &keys.user, &self.root);
        let built = build_fresh(&sync, &queue, &keys, folder.as_deref());
        let state = Unlocked { keys, kdf, sync, revision, built, keyring_folder: folder };
        if !from_cache {
            self.save_cache(&state);
        }
        *self.state.lock().await = Some(state);
        drop(queue);

        if !from_cache && let Err(e) = self.flush_queue().await {
            tracing::info!("queued changes stay queued: {e}");
        }
        let guard = self.state.lock().await;
        Ok(guard.as_ref().ok_or(BackendError::Locked)?.built.snapshot.clone())
    }

    async fn lock(&self) {
        *self.state.lock().await = None;
        // A flush in progress clears the queue itself when it finds the
        // keyring locked; never wait for its network calls here.
        if let Ok(mut queue) = self.queue.try_lock() {
            queue.clear();
        }
        self.api.lock().await.logout();
    }

    async fn refresh(&self) -> Result<Option<Snapshot>, BackendError> {
        let before = {
            let guard = self.state.lock().await;
            guard.as_ref().ok_or(BackendError::Locked)?.built.snapshot.clone()
        };
        // Before the first `/sync` of this session (offline unlock), writes
        // cannot name their owner: sync first, flush after.
        let synced = self.can_write().await;
        if synced {
            if let Err(e) = self.flush_queue().await {
                tracing::info!("queued changes stay queued: {e}");
            }
            let revision = self.api.lock().await.revision_date().await.ok();
            let guard = self.state.lock().await;
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            if revision.is_some() && revision == state.revision {
                return Ok((state.built.snapshot != before).then(|| state.built.snapshot.clone()));
            }
        }
        let (revision, sync) = self.fetch().await.map_err(map_api)?;
        {
            let queue = self.queue.lock().await;
            let mut guard = self.state.lock().await;
            let state = guard.as_mut().ok_or(BackendError::Locked)?;
            state.keyring_folder = keyring_folder(&sync, &state.keys.user, &self.root);
            state.sync = sync;
            state.revision = revision;
            self.save_cache(state);
            Self::rebuild(state, &queue);
        }
        if let Err(e) = self.flush_queue().await {
            tracing::info!("queued changes stay queued: {e}");
        }
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;
        Ok((state.built.snapshot != before).then(|| state.built.snapshot.clone()))
    }

    async fn create_collection(&self, _label: &str) -> Result<CollectionData, BackendError> {
        Err(BackendError::Rejected("collections are not supported yet".into()))
    }

    async fn delete_collection(&self, _id: &str) -> Result<(), BackendError> {
        Err(BackendError::Rejected("collections are not supported yet".into()))
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
        let mut queue = self.queue.lock().await;
        let target = {
            let guard = self.state.lock().await;
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            state.built.marked.get(&item.id).map(|m| (m.cipher_id.clone(), m.revision_date.clone()))
        };
        let Some((cid, base_revision)) = target else { return Ok(()) };
        if cid == QUEUED {
            // Never reached the server: drop it from the queue.
            queue.retain(|op| !matches!(op, Op::Create { id, .. } if *id == item.id));
            return self.queue_changed(&queue).await;
        }
        let delete = Op::Delete { id: item.id.clone(), base_revision };
        if !queue.is_empty() || !self.can_write().await {
            return self.enqueue(&mut queue, delete).await;
        }
        let sent = self.api.lock().await.trash_item(&cid).await;
        match sent {
            Ok(()) => {
                let mut guard = self.state.lock().await;
                let state = guard.as_mut().ok_or(BackendError::Locked)?;
                self.absorb(state, &queue, None, Some(&cid));
                Ok(())
            }
            Err(e) if e.is_transient() => {
                tracing::info!("offline ({e}); the change is queued");
                self.enqueue(&mut queue, delete).await
            }
            Err(e) => Err(map_api(e)),
        }
    }

    async fn describe(&self) -> String {
        let queued = self.queue.lock().await.len();
        let urls = self.api.lock().await.urls().clone();
        format!("Bitwarden {} ({}), folder \"{}\", {queued} queued change(s)", self.email, urls.identity, self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REV: &str = "2026-01-02T03:04:05Z";

    fn keys() -> Keys {
        let user = SymmetricKey::generate();
        Keys { mark: user.derive("value-mark"), user }
    }

    fn fields(k: &Keys, fields: &[(&str, &str)]) -> Value {
        Value::Array(
            fields
                .iter()
                .map(|(n, v)| json!({ "type": 0, "name": k.user.encrypt_str(n), "value": k.user.encrypt_str(v) }))
                .collect(),
        )
    }

    fn login(k: &Keys, id: &str, f: &[(&str, &str)]) -> Value {
        json!({
            "id": id, "type": 1, "revisionDate": REV, "creationDate": REV, "folderId": null,
            "name": k.user.encrypt_str(&format!("name {id}")), "notes": null,
            "login": { "username": null, "password": k.user.encrypt_str("pw"), "uris": null },
            "fields": fields(k, f),
        })
    }

    fn note(k: &Keys, id: &str, f: &[(&str, &str)], notes: &str) -> Value {
        json!({
            "id": id, "type": 2, "revisionDate": REV, "creationDate": REV, "folderId": "other",
            "name": k.user.encrypt_str(&format!("name {id}")), "notes": k.user.encrypt_str(notes),
            "secureNote": { "type": 0 }, "fields": fields(k, f),
        })
    }

    fn registry_note(k: &Keys, id: &str, json: &str) -> Value {
        note(k, id, &[("bwss:id", REGISTRY_ID), ("bwss:kind", "collections")], json)
    }

    fn sync(ciphers: Vec<Value>) -> Value {
        json!({ "profile": {}, "folders": [], "ciphers": ciphers })
    }

    fn item_ids(b: &Built) -> Vec<&str> {
        b.snapshot.items.iter().map(|i| i.id.as_str()).collect()
    }

    fn collection_ids(b: &Built) -> Vec<&str> {
        b.snapshot.collections.iter().map(|c| c.id.as_str()).collect()
    }

    #[test]
    fn build_reads_only_marked_items() {
        let k = keys();
        let mut trashed = login(&k, "c3", &[("bwss:id", "t")]);
        trashed["deletedDate"] = json!(REV);
        let s = sync(vec![
            login(&k, "c0", &[("other", "x")]),
            login(&k, "c1", &[("bwss:id", "a")]),
            note(&k, "c2", &[("bwss:id", "b"), ("bwss:collection", "Work")], "secret"),
            trashed,
            registry_note(
                &k,
                "c4",
                r#"{"home":{"label":"Home","created":1},"gone":{"label":"Gone","created":1,"deleted":true}}"#,
            ),
        ]);
        let b = build(&s, &k, None);
        assert_eq!(item_ids(&b), ["a", "b"]);
        assert_eq!(collection_ids(&b), ["home", "login", "work"]);
        assert_eq!(b.snapshot.collections[0].label, "Home");
        assert!(!b.marked.contains_key(REGISTRY_ID));
        assert_eq!(b.registry_ciphers, ["c4"]);
        assert!(!b.registry_unreadable);
        assert_eq!(&*b.marked["b"].item.secret, b"secret");
        assert!(b.unmarked.contains(&("c0".to_owned(), format!("\"{REV}\""))));
    }

    #[test]
    fn uninspectable_items_are_held() {
        let k = keys();
        let first = build(&sync(vec![login(&k, "c1", &[("bwss:id", "x")])]), &k, None);
        assert_eq!(item_ids(&first), ["x"]);
        let mut broken = login(&k, "c1", &[("bwss:id", "x")]);
        broken["key"] = json!("2.AAAA|AAAA|AAAA");
        broken["revisionDate"] = json!("2026-02-02T00:00:00Z");
        let s = sync(vec![broken]);
        assert_eq!(item_ids(&build(&s, &k, Some(&first))), ["x"]);
        // Without a previous read there is nothing to hold.
        assert!(item_ids(&build(&s, &k, None)).is_empty());
    }

    #[test]
    fn unchanged_unmarked_ciphers_are_not_rescanned() {
        let k = keys();
        let first = build(&sync(vec![login(&k, "c9", &[("other", "x")])]), &k, None);
        let cached = ("c9".to_owned(), format!("\"{REV}\""));
        assert!(first.unmarked.contains(&cached));
        let mut garbled = login(&k, "c9", &[]);
        garbled["fields"] = json!([{ "type": 0, "name": "2.bad|bad|bad", "value": "2.bad|bad|bad" }]);
        let s = sync(vec![garbled]);
        let again = build(&s, &k, Some(&first));
        assert!(again.unmarked.contains(&cached));
        // Rescanned, the same cipher cannot be read.
        assert!(!build(&s, &k, None).unmarked.contains(&cached));
    }

    #[test]
    fn several_registry_notes_merge() {
        let k = keys();
        let s = sync(vec![
            registry_note(&k, "r1", r#"{"home":{"label":"Home","created":1}}"#),
            registry_note(&k, "r2", r#"{"work":{"label":"Work","created":2}}"#),
        ]);
        let b = build(&s, &k, None);
        assert_eq!(collection_ids(&b), ["home", "login", "work"]);
        assert_eq!(b.registry.0.len(), 2);
        assert_eq!(b.registry_ciphers, ["r1", "r2"]);
        assert!(b.snapshot.items.is_empty());
    }

    #[test]
    fn unreadable_registry_is_recorded() {
        let k = keys();
        let s = sync(vec![
            registry_note(&k, "r1", r#"{"home":{"label":"Home","created":1}}"#),
            registry_note(&k, "r2", "not json"),
        ]);
        let b = build(&s, &k, None);
        assert!(b.registry_unreadable);
        assert_eq!(b.registry_ciphers, ["r1", "r2"]);
        assert_eq!(collection_ids(&b), ["home", "login"]);
    }

    #[test]
    fn reserved_id_without_kind_is_skipped() {
        let k = keys();
        let b = build(&sync(vec![login(&k, "c1", &[("bwss:id", REGISTRY_ID)])]), &k, None);
        assert!(b.snapshot.items.is_empty() && b.registry_ciphers.is_empty());
        assert_eq!(b.skipped.len(), 1);
    }

    #[test]
    fn duplicates_and_skipped_items_are_recorded() {
        let k = keys();
        let mut newer = login(&k, "c2", &[("bwss:id", "a")]);
        newer["creationDate"] = json!("2026-06-01T00:00:00Z");
        let mut card = login(&k, "c3", &[("bwss:id", "card")]);
        card["type"] = json!(3);
        let b = build(&sync(vec![newer, login(&k, "c1", &[("bwss:id", "a")]), card]), &k, None);
        assert_eq!(item_ids(&b), ["a"]);
        assert_eq!(b.marked["a"].cipher_id, "c1");
        assert_eq!(b.duplicates, vec![("a".to_owned(), vec!["c2".to_owned()])]);
        assert_eq!(b.skipped.iter().map(|(c, _)| c.as_str()).collect::<Vec<_>>(), ["c3"]);
    }

    #[test]
    fn queued_ops_are_reapplied() {
        let k = keys();
        let s = sync(vec![login(&k, "c1", &[("bwss:id", "a")]), login(&k, "c2", &[("bwss:id", "b")])]);
        let mut new = build(&s, &k, None).marked["a"].item.clone();
        new.id = "n".into();
        let queue = vec![
            Op::Create { id: "n".into(), collection: "login".into(), item: new },
            Op::Delete { id: "b".into(), base_revision: REV.into() },
        ];
        let b = build_fresh(&s, &queue, &k, None);
        assert_eq!(item_ids(&b), ["a", "n"]);
        assert_eq!(b.marked["n"].cipher_id, QUEUED);
        // The cache itself is untouched.
        assert_eq!(ciphers(&s).len(), 2);
    }

    #[test]
    fn legacy_updates_must_keep_the_item() {
        let k = keys();
        let plain = login(&k, "c1", &[("bwss:id", "a")]);
        let mut item = build(&sync(vec![plain.clone()]), &k, None).marked["a"].item.clone();
        item.secret = zeroize::Zeroizing::new(b"new".to_vec());
        let body = items::encode(&item, Some(&plain), &k.user, "").unwrap();
        assert!(encode_keeps_item(&plain, &body, &item, &k));

        // encode drops bwss:collection: the item would leave its collection.
        let elsewhere = login(&k, "c1", &[("bwss:id", "a"), ("bwss:collection", "work")]);
        let mut item = build(&sync(vec![elsewhere.clone()]), &k, None).marked["a"].item.clone();
        let body = items::encode(&item, Some(&elsewhere), &k.user, "").unwrap();
        assert!(!encode_keeps_item(&elsewhere, &body, &item, &k));

        // A relabel would rename the user's item.
        item.collection = "login".into();
        item.label = "renamed".into();
        let body = items::encode(&item, Some(&plain), &k.user, "").unwrap();
        assert!(!encode_keeps_item(&plain, &body, &item, &k));
    }

    #[test]
    fn keyring_folder_is_found_by_name() {
        let k = keys();
        let mut s = sync(vec![]);
        s["folders"] = json!([
            { "id": "f2", "name": k.user.encrypt_str("secret-service") },
            { "id": "f1", "name": k.user.encrypt_str("secret-service") },
            { "id": "f0", "name": k.user.encrypt_str("other") },
        ]);
        assert_eq!(keyring_folder(&s, &k.user, "secret-service").as_deref(), Some("f1"));
        assert_eq!(keyring_folder(&s, &k.user, "nope"), None);
    }

    #[test]
    fn offline_cache_is_versioned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.json");
        // A legacy cache (no format) is set aside, never read.
        std::fs::write(&path, r#"{"kdf":{"pbkdf2":{"iterations":1}},"email":"a@b.c","sync":{}}"#).unwrap();
        assert!(load_cache(&path, "a@b.c").unwrap().is_none());
        assert!(dir.path().join("sync.json.legacy").exists());
        // An unreadable one refuses the offline unlock and stays in place.
        std::fs::create_dir(&path).unwrap();
        let err = load_cache(&path, "a@b.c").err().unwrap().to_string();
        assert!(err.contains(&path.display().to_string()), "{err}");
        assert!(path.exists());
    }

    #[test]
    fn queue_file_is_sealed_and_set_aside_when_foreign() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");
        let key = SymmetricKey::generate();
        std::fs::write(&path, serde_json::to_vec(&seal(&[], &key)).unwrap()).unwrap();
        assert!(load_queue(&path, &key).unwrap().is_empty());
        assert!(path.exists());
        assert!(load_queue(&path, &SymmetricKey::generate()).unwrap().is_empty());
        assert!(!path.exists());
        assert!(dir.path().join("queue.json.unsealable").exists());
    }
}
