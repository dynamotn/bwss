//! Bitwarden backend: the keyring is every vault item marked with `bwss:id`
//! (design §3, §8).
//!
//! * Online: API-key login, `/sync`, writes straight to the server.
//! * Offline: the last sync response (still Bitwarden ciphertext) is cached,
//!   so the keyring unlocks and reads without a network; writes are queued,
//!   shown at once, and replayed in order on the next successful refresh.
//!
//! Writes go through the op runner (`runner.rs`): bwss changes only its own
//! fields and the value source of an item (design §5).

use std::borrow::{Borrow, Cow};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use super::ops::{
    FORMAT as LEGACY_QUEUE_FORMAT, Loaded, Op, QUEUE_FORMAT, read_formats, read_versioned, seal, set_aside, unseal,
};
use super::registry::{REGISTRY_ID, Registry};
use super::runner::{Effect, status_lines};
use super::{AclTrust, Backend, BackendError};
use crate::bw::api::{Api, ApiError, ApiKey, resolve_server_urls};
use crate::bw::crypto::{CryptoError, KdfParams, SymmetricKey, derive_master_key};
use crate::bw::fields::{F_KIND, field_names, field_value, first_index};
use crate::bw::items::item_key;
use crate::bw::scan::{Keys, MarkedItem, Scan, is_blob, normalize_collection, resolve_duplicates, scan};
use crate::bw::write::{apply, new_note};
use crate::config::{Config, Credentials, Paths};
use crate::fsutil::{write_json_private, write_private};
use crate::model::{CollectionData, ItemData, LOGIN_COLLECTION, SESSION_COLLECTION, Snapshot};

const FORMAT: u64 = 2;
const TYPE_SECURE_NOTE: u64 = 2;
/// `bwss:kind` of the collection registry note.
pub(super) const KIND_COLLECTIONS: &str = "collections";
/// Cipher id of an item created by a queued op: it is not on the server yet.
pub(super) const QUEUED: &str = "";

/// `sync.json`: the last `/sync` response, still ciphertext. The `format`
/// key is written (`CacheRef`) but not read back.
#[derive(Deserialize)]
struct Cache {
    kdf: KdfParams,
    email: String,
    /// Raw `/accounts/revision-date` answer at the time of the sync.
    #[serde(default)]
    revision: Option<String>,
    sync: Value,
}

/// What `save_cache` writes: `Cache` by reference, so a write never copies
/// the vault.
#[derive(Serialize)]
struct CacheRef<'a> {
    format: u64,
    kdf: KdfParams,
    email: &'a str,
    revision: Option<&'a str>,
    sync: &'a Value,
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
    pub registry_unreadable: bool,
    /// `(bwss:id, losing cipher ids)`.
    pub duplicates: Vec<(String, Vec<String>)>,
    /// `(cipher id, reason)` of marked items that are not supported.
    pub skipped: Vec<(String, String)>,
    /// Scan cache: `(cipher id, raw revisionDate)` of unmarked ciphers.
    pub unmarked: HashSet<(String, String)>,
}

/// Whether a message about `what` is logged for the first time in this
/// process, so a rebuild does not repeat it. Only a hash is kept.
fn first_report(what: impl std::hash::Hash) -> bool {
    use std::hash::Hasher;
    static SEEN: std::sync::OnceLock<std::sync::Mutex<HashSet<u64>>> = std::sync::OnceLock::new();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    what.hash(&mut h);
    SEEN.get_or_init(Default::default).lock().map_or(true, |mut seen| seen.insert(h.finish()))
}

/// Scan-cache key of a cipher; `None` when it has no revision to compare.
pub(super) fn cache_key(cipher: &Value) -> Option<(String, String)> {
    let id = cipher.get("id").and_then(Value::as_str).filter(|id| !id.is_empty())?;
    let rev = cipher.get("revisionDate").filter(|r| !r.is_null())?;
    Some((id.to_owned(), rev.to_string()))
}

pub(super) fn ciphers(sync: &Value) -> &[Value] {
    sync.get("ciphers").and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// Why a registry note could not be read.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RegistryError {
    /// The item key of the note does not decrypt.
    Key,
    /// The field names or the `bwss:kind` value do not decrypt.
    Fields,
    /// The notes do not decrypt.
    Notes,
    /// The notes are not a registry document.
    Parse,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Key => "its item key does not decrypt",
            Self::Fields => "its fields do not decrypt",
            Self::Notes => "its notes do not decrypt",
            Self::Parse => "its notes are not a collection registry",
        })
    }
}

/// A marked item with the registry id: `Ok(Some)` for a registry note,
/// `Ok(None)` for anything else, `Err` when its notes cannot be read.
pub(super) fn read_registry(cipher: &Value, keys: &Keys) -> Result<Option<Registry>, RegistryError> {
    use RegistryError::{Fields, Key, Notes, Parse};
    if cipher.get("type").and_then(Value::as_u64) != Some(TYPE_SECURE_NOTE) {
        return Ok(None);
    }
    let key = item_key(cipher, &keys.user).map_err(|_| Key)?;
    let names = field_names(cipher, &key).map_err(|_| Fields)?;
    let Some(i) = first_index(&names, F_KIND) else { return Ok(None) };
    if field_value(cipher, i, &key).map_err(|_| Fields)?.trim() != KIND_COLLECTIONS {
        return Ok(None);
    }
    let notes = match cipher.get("notes").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => key.decrypt_str(s).map_err(|_| Notes)?,
        _ => return Ok(Some(Registry::default())),
    };
    if notes.trim().is_empty() {
        return Ok(Some(Registry::default()));
    }
    Registry::try_parse(&notes).map(Some).map_err(|_| Parse)
}

/// Builds the keyring from a copy of the vault (design §8.2 step 4).
///
/// `previous` supplies the scan cache (unchanged unmarked ciphers are not
/// decrypted again) and the items to hold: a marked item whose cipher can
/// no longer be inspected stays as last read (§3.4).
pub(crate) fn build(sync: &Value, keys: &Keys, previous: Option<&Built>) -> Built {
    build_list(ciphers(sync), keys, previous)
}

/// `build` over a list of ciphers, owned or borrowed.
fn build_list<C: Borrow<Value>>(list: &[C], keys: &Keys, previous: Option<&Built>) -> Built {
    let held: HashMap<&str, &MarkedItem> =
        previous.map(|p| p.marked.values().map(|m| (m.cipher_id.as_str(), m)).collect()).unwrap_or_default();
    let mut found = Vec::new();
    let mut unmarked = HashSet::new();
    let mut skipped = Vec::new();
    let mut blobs = std::collections::BTreeSet::new();
    let mut registry = Registry::default();
    let mut registry_ciphers = Vec::new();
    let mut registry_unreadable = false;

    for cipher in list.iter().map(Borrow::borrow) {
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
                Err(why) => {
                    tracing::warn!(cipher = cid, "the collection registry cannot be read: {why}");
                    registry_unreadable = true;
                    registry_ciphers.push(cid.to_owned());
                }
            },
            Scan::Marked(m) => found.push(*m),
            Scan::Uninspectable(why) => {
                // Organization and blob items are never read: not worth a warning
                // each (blobs are counted once per unlock).
                if cipher.get("organizationId").is_some_and(|o| !o.is_null()) || is_blob(cipher) {
                    tracing::debug!("{why}");
                } else if first_report(("uninspectable", &key)) {
                    tracing::warn!("{why}");
                }
                if cid.is_empty() {
                    continue;
                }
                if is_blob(cipher) && cipher.get("organizationId").is_none_or(Value::is_null) {
                    blobs.insert(cid.to_owned());
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

    let mut items: Vec<ItemData> = winners.iter().map(|m| m.item.clone()).collect();
    items.sort_by(|a, b| a.id.cmp(&b.id));

    let ciphers = winners.iter().map(|m| (m.item.id.clone(), m.cipher_id.clone())).collect();
    Built {
        snapshot: Snapshot { collections: collection_list(&registry, &items), items, ciphers, blobs },
        marked: winners.into_iter().map(|m| (m.item.id.clone(), m)).collect(),
        registry,
        registry_ciphers,
        registry_unreadable,
        duplicates,
        skipped,
        unmarked,
    }
}

/// The collections shown: `login`, the registry's live entries and every
/// collection an item uses (design §4).
fn collection_list(registry: &Registry, items: &[ItemData]) -> Vec<CollectionData> {
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
    for item in items {
        collections.entry(item.collection.clone()).or_insert_with(|| CollectionData {
            id: item.collection.clone(),
            label: item.collection.clone(),
            created: 0,
            modified: 0,
        });
    }
    collections.into_values().collect()
}

/// The registry with the queued collection changes applied.
pub(super) fn registry_with_queue(registry: &Registry, queue: &[Op]) -> Registry {
    let mut shown = registry.clone();
    for op in queue {
        if let Op::Registry { collection, entry } = op {
            shown.put(collection, entry.clone());
        }
    }
    shown
}

/// The winning marked cipher of every `bwss:id` in `list`, as its index.
/// A winner that is a queued create has no server cipher and is left out.
fn marked_positions<C: Borrow<Value>>(
    list: &[C],
    keys: &Keys,
    unmarked: &HashSet<(String, String)>,
) -> HashMap<String, usize> {
    let mut found = Vec::new();
    for c in list.iter().map(Borrow::borrow) {
        if cache_key(c).is_some_and(|k| unmarked.contains(&k)) {
            continue;
        }
        if let Scan::Marked(m) = scan(c, keys) {
            found.push(*m);
        }
    }
    let (winners, _) = resolve_duplicates(found);
    let mut by_cipher: HashMap<&str, usize> = HashMap::new();
    for (i, c) in list.iter().map(Borrow::borrow).enumerate() {
        if let Some(cid) = c.get("id").and_then(Value::as_str) {
            by_cipher.entry(cid).or_insert(i);
        }
    }
    winners
        .into_iter()
        .filter(|m| m.cipher_id != QUEUED)
        .filter_map(|m| by_cipher.get(m.cipher_id.as_str()).map(|&i| (m.item.id, i)))
        .collect()
}

/// Index in `list` of the cipher that holds `id` on the server.
pub(super) fn find_marked<C: Borrow<Value>>(
    list: &[C],
    id: &str,
    keys: &Keys,
    unmarked: &HashSet<(String, String)>,
) -> Option<usize> {
    marked_positions(list, keys, unmarked).get(id).copied()
}

/// The ciphers with every queued op applied, so pending writes stay visible
/// (design §8.2 step 3). Only the ciphers the ops touch are copied; the rest
/// stay borrowed from `sync`.
pub(super) fn with_queue<'a>(
    sync: &'a Value,
    queue: &[Op],
    keys: &Keys,
    folder: Option<&str>,
    unmarked: &HashSet<(String, String)>,
) -> Vec<Cow<'a, Value>> {
    let mut list: Vec<Cow<'a, Value>> = ciphers(sync).iter().map(Cow::Borrowed).collect();
    // Positions stay valid across patches, so one scan serves a run of them:
    // `apply` edits only bwss's own fields and the value source, so a patch
    // never changes `bwss:id`, and the patched cipher keeps its id and dates
    // (restored below), so it still wins its `bwss:id` at the same index.
    // Organization ciphers are never `Marked` (`scan` refuses to read them),
    // so they are never in the map and never patched. A create appends a
    // cipher that may win or lose a duplicate id, and a delete shifts every
    // later index, so both drop the map and the next op scans again.
    let mut positions: Option<HashMap<String, usize>> = None;
    for op in queue {
        match op {
            Op::Create { item, .. } => match new_note(item, folder, keys) {
                Ok(mut body) => {
                    body.insert("id".into(), json!(QUEUED));
                    list.push(Cow::Owned(Value::Object(body)));
                    positions = None;
                }
                Err(e) => tracing::warn!("a queued new item cannot be shown: {e}"),
            },
            Op::Patch(patch) => {
                let map = positions.get_or_insert_with(|| marked_positions(&list, keys, unmarked));
                let Some(&i) = map.get(&patch.id) else { continue };
                let Some(current) = list.get(i) else { continue };
                match apply(current, patch, keys) {
                    Ok(mut body) => {
                        body.remove("lastKnownRevisionDate");
                        for k in ["id", "revisionDate", "creationDate"] {
                            if let Some(v) = current.get(k) {
                                body.insert(k.into(), v.clone());
                            }
                        }
                        if let Some(slot) = list.get_mut(i) {
                            *slot = Cow::Owned(Value::Object(body));
                        }
                    }
                    Err(e) => {
                        if first_report(("unshown", &patch.id, &patch.base_revision)) {
                            tracing::warn!("a queued change cannot be shown: {e}");
                        }
                    }
                }
            }
            Op::Delete { id, .. } => {
                let map = positions.get_or_insert_with(|| marked_positions(&list, keys, unmarked));
                if let Some(&i) = map.get(id) {
                    list.remove(i);
                    positions = None;
                }
            }
            // Shown through `build_view`: the registry note is merged, never
            // rewritten here.
            Op::Registry { .. } => {}
        }
    }
    list
}

/// Builds the keyring from the cache with the queue applied.
fn build_view(sync: &Value, queue: &[Op], keys: &Keys, folder: Option<&str>, previous: Option<&Built>) -> Built {
    let mut built = if queue.is_empty() {
        build(sync, keys, previous)
    } else {
        let none = HashSet::new();
        let unmarked = previous.map_or(&none, |p| &p.unmarked);
        build_list(&with_queue(sync, queue, keys, folder, unmarked), keys, previous)
    };
    if queue.iter().any(|op| matches!(op, Op::Registry { .. })) {
        // `built.registry` stays the server's: only what is shown changes.
        let shown = registry_with_queue(&built.registry, queue);
        built.snapshot.collections = collection_list(&shown, &built.snapshot.items);
    }
    built
}

/// Builds the keyring for a freshly loaded cache and queue.
fn build_fresh(sync: &Value, queue: &[Op], keys: &Keys, folder: Option<&str>) -> Built {
    let base = build(sync, keys, None);
    if queue.is_empty() {
        return base;
    }
    build_view(sync, queue, keys, folder, Some(&base))
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

/// The key `queue.json` is sealed with: the user key derived for "queue".
/// A same-user process can get text of its choice encrypted under the user
/// key itself (any field of an item it creates), so that key must never open
/// the queue once this device moved to the queue key (design §8.1).
pub(super) fn queue_key(user: &SymmetricKey) -> SymmetricKey {
    user.derive("queue")
}

/// Sets the flag that closes the one-time migration window.
fn end_migration(flag: &Path) {
    if !crate::config::flag_set(flag)
        && let Err(e) = crate::config::set_flag(flag, true, b"done\n")
    {
        tracing::warn!(path = %flag.display(), "could not record that the queue moved to its key: {e}");
    }
}

/// Reads `queue.json`: format 3 under `queue_key(user)`. A format-2 queue
/// (sealed with the user key itself by an older bwss) is opened with the
/// user key only while `migrated` is absent, and is then resealed and the
/// flag set. Anything that does not open is set aside, never replayed.
fn load_queue(path: &Path, user: &SymmetricKey, migrated: &Path) -> Result<Vec<Op>, BackendError> {
    let refuse = |e: std::io::Error| {
        unavailable(format!("cannot read the write queue {}: {e}; it is left untouched", path.display()))
    };
    let key = queue_key(user);
    match read_formats(path, "legacy", &[LEGACY_QUEUE_FORMAT, QUEUE_FORMAT]) {
        Loaded::Ok(v) => {
            let legacy = v.get("format").and_then(Value::as_u64) == Some(LEGACY_QUEUE_FORMAT);
            let opened = match (legacy, crate::config::flag_set(migrated)) {
                (false, _) => unseal(&v, &key).map_err(|e| e.to_string()),
                (true, false) => unseal(&v, user).map_err(|e| e.to_string()),
                (true, true) => Err("it is sealed the old way, and this device already moved to the queue key".into()),
            };
            match opened {
                Ok(ops) if legacy => {
                    // When the reseal fails, the file stays as it was and the
                    // window stays open for the next unlock.
                    match write_json_private(path, &seal(&ops, &key)) {
                        Ok(()) => end_migration(migrated),
                        Err(e) => tracing::warn!(path = %path.display(), "could not reseal the write queue: {e}"),
                    }
                    Ok(ops)
                }
                Ok(ops) => {
                    end_migration(migrated);
                    Ok(ops)
                }
                Err(why) => {
                    tracing::warn!(path = %path.display(), "the write queue cannot be opened ({why}); setting it aside");
                    match set_aside(path, "unsealable") {
                        Loaded::Unreadable(e) => Err(refuse(e)),
                        _ => Ok(Vec::new()),
                    }
                }
            }
        }
        Loaded::Missing => {
            end_migration(migrated);
            Ok(Vec::new())
        }
        Loaded::SetAside(to) => {
            tracing::warn!(moved_to = %to.display(), "changes queued by an older version are not replayed");
            Ok(Vec::new())
        }
        Loaded::Unreadable(e) => Err(refuse(e)),
    }
}

pub(super) struct Unlocked {
    pub(super) keys: Keys,
    kdf: KdfParams,
    /// The server's copy of the vault, as cached; queued ops are not in it.
    pub(super) sync: Value,
    /// Raw account revision date of `sync`, when known.
    revision: Option<String>,
    /// The keyring: `sync` with the queue applied.
    pub(super) built: Built,
    pub(super) keyring_folder: Option<String>,
}

pub struct BitwardenBackend {
    email: String,
    /// Name of the keyring folder.
    pub(super) root: String,
    pub(super) api: Mutex<Api>,
    key: ApiKey,
    pub(super) state: Mutex<Option<Unlocked>>,
    cache_path: PathBuf,
    queue_path: PathBuf,
    /// Device flag: the queue moved to the queue key, so a queue under the
    /// user key is never opened again.
    queue_migrated: PathBuf,
    /// Queued ops; loaded at unlock (it is sealed with the queue key) and
    /// dropped at lock. Lock order: `queue`, then `state`.
    pub(super) queue: Mutex<Vec<Op>>,
}

fn unavailable(e: impl std::fmt::Display) -> BackendError {
    BackendError::Unavailable(e.to_string())
}

fn map_api(e: ApiError) -> BackendError {
    if e.is_transient() { BackendError::Unavailable(e.to_string()) } else { BackendError::Rejected(e.to_string()) }
}

impl BitwardenBackend {
    pub fn new(config: &Config, creds: Credentials, paths: &Paths) -> anyhow::Result<Self> {
        let urls = resolve_server_urls(&config.server_url).map_err(anyhow::Error::msg)?;
        let profile = config.profile.as_deref().ok_or_else(|| anyhow::anyhow!("no profile to serve"))?;
        let device_path = paths.device_id(profile);
        let device_id = match std::fs::read_to_string(&device_path) {
            Ok(s) if !s.trim().is_empty() => s.trim().to_owned(),
            _ => {
                let id = uuid::Uuid::new_v4().to_string();
                write_private(&device_path, id.as_bytes())?;
                id
            }
        };
        let queue_path = paths.state.join("queue.json");
        // Nothing to migrate: close the window before any unlock.
        if std::fs::symlink_metadata(&queue_path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
            end_migration(&paths.queue_key_migrated());
        }
        Ok(BitwardenBackend {
            email: config.email.clone(),
            root: config.folder.trim_matches('/').to_owned(),
            api: Mutex::new(Api::new(urls, device_id)?),
            key: ApiKey {
                origin: creds.identity_origin,
                client_id: creds.client_id,
                client_secret: creds.client_secret,
            },
            state: Mutex::new(None),
            cache_path: paths.cache.join("sync.json"),
            queue_path,
            queue_migrated: paths.queue_key_migrated(),
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
    pub(super) async fn can_write(&self) -> bool {
        self.ensure_login().await.is_ok() && self.api.lock().await.has_profile()
    }

    fn save_cache(&self, state: &Unlocked) {
        let cache = CacheRef {
            format: FORMAT,
            kdf: state.kdf,
            email: &self.email,
            revision: state.revision.as_deref(),
            sync: &state.sync,
        };
        if let Err(e) = write_json_private(&self.cache_path, &cache) {
            tracing::warn!("could not write the offline cache: {e}");
        }
    }

    /// Writes the queue, sealed with the queue key of `user`.
    pub(super) fn save_queue(&self, queue: &[Op], user: &SymmetricKey) -> std::io::Result<()> {
        let saved = write_json_private(&self.queue_path, &seal(queue, &queue_key(user)));
        if let Err(e) = &saved {
            tracing::warn!("could not write the offline queue: {e}");
        }
        saved
    }

    /// Rebuilds the keyring after the cache or the queue changed.
    pub(super) fn rebuild(state: &mut Unlocked, queue: &[Op]) {
        state.built = build_view(&state.sync, queue, &state.keys, state.keyring_folder.as_deref(), Some(&state.built));
    }

    /// Records what the server did in the cache, so later edits build on it.
    pub(super) fn absorb(&self, state: &mut Unlocked, queue: &[Op], effect: Effect) {
        if let Some(list) = state.sync.get_mut("ciphers").and_then(Value::as_array_mut) {
            match effect {
                Effect::Nothing => {}
                Effect::Trashed(gone) => list.retain(|c| c.get("id").and_then(Value::as_str) != Some(&gone)),
                Effect::Saved(server) => {
                    let c = crate::bw::api::normalize_keys(server);
                    if let Some(cid) = c.get("id").and_then(Value::as_str).map(str::to_owned) {
                        list.retain(|x| x.get("id").and_then(Value::as_str) != Some(&cid));
                        list.push(c);
                    }
                }
            }
        }
        // Keep the offline copy current, so that what was written is still
        // there when the next unlock happens without a network.
        self.save_cache(state);
        Self::rebuild(state, queue);
    }

    /// Keeps the queue on disk and shows it.
    pub(super) async fn queue_changed(&self, queue: &[Op]) -> Result<(), BackendError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        // Logged in `save_queue`; the change is already in memory.
        let _ = self.save_queue(queue, &state.keys.user);
        Self::rebuild(state, queue);
        Ok(())
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
        *queue = load_queue(&self.queue_path, &keys.user, &self.queue_migrated)?;
        let folder = keyring_folder(&sync, &keys.user, &self.root);
        let built = build_fresh(&sync, &queue, &keys, folder.as_deref());
        if !built.snapshot.blobs.is_empty() {
            tracing::warn!(
                "{} Bitwarden item(s) use the newer encryption format and cannot be read",
                built.snapshot.blobs.len()
            );
        }
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

    async fn create_collection(&self, label: &str) -> Result<CollectionData, BackendError> {
        let mut queue = self.queue.lock().await;
        let result = self.create_collection_locked(&mut queue, label).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    async fn delete_collection(&self, id: &str, items: &[String]) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        let result = self.delete_collection_locked(&mut queue, id, items).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    async fn put_item(&self, item: &ItemData) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        let result = self.put_locked(&mut queue, item).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    async fn delete_item(&self, item: &ItemData) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        let result = self.delete_locked(&mut queue, &item.id).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    async fn acl_trust(&self) -> Result<AclTrust, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;
        Ok(AclTrust::PerDevice(state.keys.user.derive("acl-confirm")))
    }

    async fn describe(&self) -> String {
        let queued = self.queue.lock().await.len();
        let urls = self.api.lock().await.urls().clone();
        let mut out = format!(
            "Bitwarden {} ({}), folder \"{}\", {queued} queued change(s)",
            self.email, urls.identity, self.root
        );
        if let Some(state) = self.state.lock().await.as_ref() {
            for line in status_lines(&state.built) {
                out.push('\n');
                out.push_str(&line);
            }
        }
        out
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::bw::write::{Patch, ValueChange};

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
    fn read_registry_reports_why() {
        let k = keys();
        let other = SymmetricKey::generate();
        let kind = [("bwss:id", REGISTRY_ID), ("bwss:kind", "collections")];

        let good = registry_note(&k, "r", r#"{"home":{"label":"Home","created":1}}"#);
        assert_eq!(read_registry(&good, &k).unwrap().unwrap().0.len(), 1);
        assert_eq!(read_registry(&login(&k, "c", &[("bwss:id", "x")]), &k), Ok(None));

        assert_eq!(read_registry(&registry_note(&k, "r", "not json"), &k), Err(RegistryError::Parse));

        let mut notes = registry_note(&k, "r", "{}");
        notes["notes"] = json!(other.encrypt_str("{}"));
        assert_eq!(read_registry(&notes, &k), Err(RegistryError::Notes));

        let mut fields = note(&k, "r", &kind, "{}");
        fields["fields"] = self::fields(&Keys { mark: other.derive("value-mark"), user: other }, &kind);
        assert_eq!(read_registry(&fields, &k), Err(RegistryError::Fields));

        let mut item_key = note(&k, "r", &kind, "{}");
        item_key["key"] = json!(SymmetricKey::generate().encrypt_str("garbage"));
        assert_eq!(read_registry(&item_key, &k), Err(RegistryError::Key));
    }

    #[test]
    fn a_queued_view_copies_only_the_ciphers_the_ops_touch() {
        let k = keys();
        let s = sync(vec![
            login(&k, "c1", &[("bwss:id", "a")]),
            login(&k, "c2", &[("bwss:id", "b")]),
            login(&k, "c3", &[("bwss:id", "c")]),
        ]);
        let queue = [Op::Delete { id: "b".into(), base_revision: REV.into(), cipher_id: Some("c2".into()) }];
        let view = with_queue(&s, &queue, &k, None, &HashSet::new());
        let ids: Vec<_> = view.iter().map(|c| c["id"].as_str().unwrap().to_owned()).collect();
        assert_eq!(ids, ["c1", "c3"]);
        assert!(view.iter().all(|c| matches!(c, Cow::Borrowed(_))), "nothing was copied");
        assert_eq!(ciphers(&s).len(), 3, "the cache is untouched");
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
            Op::Delete { id: "b".into(), base_revision: REV.into(), cipher_id: Some("c2".into()) },
        ];
        let b = build_fresh(&s, &queue, &k, None);
        assert_eq!(item_ids(&b), ["a", "n"]);
        assert_eq!(b.marked["n"].cipher_id, QUEUED);
        // The cache itself is untouched.
        assert_eq!(ciphers(&s).len(), 2);
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

    fn one_op() -> Vec<Op> {
        vec![Op::Delete { id: "a".into(), base_revision: REV.into(), cipher_id: Some("c1".into()) }]
    }

    fn read_file(path: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    /// A queue as bwss wrote it before the queue key: format 2, sealed with
    /// the user key itself. A same-user process can forge exactly this.
    fn legacy_queue(user: &SymmetricKey) -> Vec<u8> {
        let mut file = seal(&one_op(), user);
        file["format"] = json!(2);
        serde_json::to_vec(&file).unwrap()
    }

    struct QueueDir {
        _dir: tempfile::TempDir,
        path: PathBuf,
        flag: PathBuf,
        aside: PathBuf,
    }

    fn queue_dir() -> QueueDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/queue.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let flag = dir.path().join("tool-state/queue-key-migrated");
        let aside = dir.path().join("state/queue.json.unsealable");
        QueueDir { _dir: dir, path, flag, aside }
    }

    #[test]
    fn the_queue_is_sealed_with_a_key_of_its_own_as_format_3() {
        let q = queue_dir();
        let user = SymmetricKey::generate();
        let file = seal(&one_op(), &queue_key(&user));
        assert_eq!(file["format"], 3);
        std::fs::write(&q.path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert_eq!(load_queue(&q.path, &user, &q.flag).unwrap().len(), 1);
        assert!(q.path.exists());
        assert!(crate::config::flag_set(&q.flag), "a queue under the queue key means the move is done");
    }

    #[test]
    fn a_pre_migration_queue_is_resealed_once_and_the_flag_set() {
        let q = queue_dir();
        let user = SymmetricKey::generate();
        std::fs::write(&q.path, legacy_queue(&user)).unwrap();
        assert_eq!(load_queue(&q.path, &user, &q.flag).unwrap().len(), 1);
        let resealed = read_file(&q.path);
        assert_eq!(resealed["format"], 3);
        assert_eq!(unseal(&resealed, &queue_key(&user)).unwrap().len(), 1);
        assert!(crate::config::flag_set(&q.flag));
        assert_eq!(load_queue(&q.path, &user, &q.flag).unwrap().len(), 1);
        assert!(!q.aside.exists());
    }

    #[test]
    fn a_forged_user_key_queue_after_the_migration_is_never_replayed() {
        let user = SymmetricKey::generate();
        // Format 2 under the user key, and the same ciphertext labelled format 3.
        let forged_v3 = {
            let mut file = seal(&one_op(), &user);
            file["format"] = json!(3);
            serde_json::to_vec(&file).unwrap()
        };
        for forged in [legacy_queue(&user), forged_v3] {
            let q = queue_dir();
            crate::config::set_flag(&q.flag, true, b"done\n").unwrap();
            std::fs::write(&q.path, &forged).unwrap();
            assert!(load_queue(&q.path, &user, &q.flag).unwrap().is_empty(), "nothing is replayed");
            assert!(!q.path.exists());
            assert_eq!(std::fs::read(&q.aside).unwrap(), forged, "set aside as it was");
        }
    }

    #[test]
    fn no_queue_at_all_ends_the_migration_window() {
        let q = queue_dir();
        let user = SymmetricKey::generate();
        assert!(load_queue(&q.path, &user, &q.flag).unwrap().is_empty());
        assert!(crate::config::flag_set(&q.flag));
        // A user-key queue planted afterwards is not opened with the user key.
        std::fs::write(&q.path, legacy_queue(&user)).unwrap();
        assert!(load_queue(&q.path, &user, &q.flag).unwrap().is_empty());
        assert!(q.aside.exists());
    }

    #[test]
    fn a_queue_that_cannot_be_resealed_is_still_read_and_left_as_it_was() {
        let q = queue_dir();
        let user = SymmetricKey::generate();
        let old = legacy_queue(&user);
        std::fs::write(&q.path, &old).unwrap();
        // The private write goes through this temporary name: a directory
        // there makes it fail, even for root.
        std::fs::create_dir(crate::fsutil::temp_path(&q.path)).unwrap();
        assert_eq!(load_queue(&q.path, &user, &q.flag).unwrap().len(), 1);
        assert_eq!(std::fs::read(&q.path).unwrap(), old);
        assert!(!crate::config::flag_set(&q.flag), "not moved yet: the window stays for the next try");
    }

    #[test]
    fn a_queue_that_opens_with_neither_key_is_kept_aside() {
        let q = queue_dir();
        let foreign = serde_json::to_vec(&seal(&one_op(), &SymmetricKey::generate())).unwrap();
        std::fs::write(&q.path, &foreign).unwrap();
        assert!(load_queue(&q.path, &SymmetricKey::generate(), &q.flag).unwrap().is_empty());
        assert!(!q.path.exists());
        assert_eq!(std::fs::read(&q.aside).unwrap(), foreign, "set aside as it was, never lost");
    }

    #[test]
    fn registry_errors_say_why() {
        for (why, text) in [
            (RegistryError::Key, "its item key does not decrypt"),
            (RegistryError::Fields, "its fields do not decrypt"),
            (RegistryError::Notes, "its notes do not decrypt"),
            (RegistryError::Parse, "its notes are not a collection registry"),
        ] {
            assert_eq!(why.to_string(), text);
        }
    }

    #[test]
    fn only_a_note_of_the_registry_kind_is_a_registry() {
        let k = keys();
        let other_kind = note(&k, "r", &[("bwss:id", REGISTRY_ID), ("bwss:kind", "something-else")], "{}");
        assert_eq!(read_registry(&other_kind, &k), Ok(None));

        // No notes, or notes of white space only: an empty registry.
        let mut no_notes = registry_note(&k, "r", "{}");
        no_notes["notes"] = Value::Null;
        assert!(read_registry(&no_notes, &k).unwrap().unwrap().0.is_empty());
        let mut empty_notes = registry_note(&k, "r", "{}");
        empty_notes["notes"] = json!("");
        assert!(read_registry(&empty_notes, &k).unwrap().unwrap().0.is_empty());
        assert!(read_registry(&registry_note(&k, "r", " \n "), &k).unwrap().unwrap().0.is_empty());
    }

    fn broken(mut cipher: Value) -> Value {
        cipher["key"] = json!("2.AAAA|AAAA|AAAA");
        cipher
    }

    #[test]
    fn organization_items_and_items_without_an_id_are_ignored() {
        let k = keys();
        let mut org = login(&k, "c8", &[("bwss:id", "z")]);
        org["organizationId"] = json!("org1");
        let mut anonymous = broken(login(&k, "c9", &[("bwss:id", "y")]));
        anonymous.as_object_mut().unwrap().remove("id");
        let first = build(&sync(vec![login(&k, "c1", &[("bwss:id", "x")])]), &k, None);
        assert_eq!(item_ids(&first), ["x"]);
        // Held items are looked up by cipher id: neither of these is one.
        let b = build(&sync(vec![org, anonymous]), &k, Some(&first));
        assert!(b.snapshot.items.is_empty() && b.marked.is_empty());
        assert!(b.skipped.is_empty() && b.registry_ciphers.is_empty() && !b.registry_unreadable);
    }

    #[test]
    fn a_registry_that_cannot_be_inspected_is_held_as_last_read() {
        let k = keys();
        let note = registry_note(&k, "r1", r#"{"home":{"label":"Home","created":1}}"#);
        let first = build(&sync(vec![note.clone()]), &k, None);
        assert!(!first.registry_unreadable);

        let mut changed = broken(note);
        changed["revisionDate"] = json!("2026-02-02T00:00:00Z");
        let b = build(&sync(vec![changed]), &k, Some(&first));
        assert_eq!(collection_ids(&b), ["home", "login"], "the registry as last read");
        assert_eq!(b.registry_ciphers, ["r1"]);
        assert!(b.registry_unreadable, "it must never be written over");
        // Without a previous read there is nothing to hold, and nothing to protect.
        let b = build(&sync(vec![broken(registry_note(&k, "r1", "{}"))]), &k, None);
        assert!(b.registry_ciphers.is_empty() && !b.registry_unreadable);
    }

    #[test]
    fn registry_entries_never_shadow_the_built_in_collections() {
        let k = keys();
        let s = sync(vec![registry_note(
            &k,
            "r1",
            r#"{"login":{"label":"Shadow","created":1},"default":{"label":"Alias","created":1},
                "session":{"label":"Session","created":1},"home":{"label":"Home","created":1}}"#,
        )]);
        let b = build(&s, &k, None);
        assert_eq!(collection_ids(&b), ["home", "login"]);
        assert_eq!(b.snapshot.collections[1].label, "Login");
    }

    fn label_patch(id: &str, label: &str) -> Op {
        Op::Patch(Patch {
            id: id.into(),
            base_revision: REV.into(),
            set: vec![("bwss:label".into(), label.into(), false)],
            remove: vec![],
            acl_add: vec![],
            value: ValueChange::Keep,
            cipher_id: None,
        })
    }

    fn view_labels(view: &[Cow<'_, Value>], k: &Keys) -> Vec<(String, String)> {
        let b = build_list(view, k, None);
        let mut out: Vec<_> = b.marked.values().map(|m| (m.item.id.clone(), m.item.label.clone())).collect();
        out.sort();
        out
    }

    #[test]
    fn a_run_of_queued_ops_keeps_every_patch_on_its_own_cipher() {
        // One scan serves the patches between creates and deletes: patch a,
        // patch b, create d, patch a, delete b, patch c.
        let k = keys();
        let s = sync(vec![
            login(&k, "c1", &[("bwss:id", "a")]),
            login(&k, "c2", &[("bwss:id", "b")]),
            login(&k, "c3", &[("bwss:id", "c")]),
        ]);
        let mut d = build(&s, &k, None).marked["a"].item.clone();
        d.id = "d".into();
        d.label = "created".into();
        let queue = vec![
            label_patch("a", "a1"),
            label_patch("b", "b1"),
            Op::Create { id: "d".into(), collection: "login".into(), item: d },
            label_patch("a", "a2"),
            Op::Delete { id: "b".into(), base_revision: REV.into(), cipher_id: Some("c2".into()) },
            label_patch("c", "c1"),
        ];
        let view = with_queue(&s, &queue, &k, None, &HashSet::new());
        let ids: Vec<_> = view.iter().map(|c| c["id"].as_str().unwrap().to_owned()).collect();
        assert_eq!(ids, ["c1", "c3", ""], "b is gone, d is queued, nothing else moved");
        assert_eq!(
            view_labels(&view, &k),
            [("a".into(), "a2".into()), ("c".into(), "c1".into()), ("d".into(), "created".into())]
        );
        // Every patched cipher still carries its own bwss:id and its dates.
        let built = build_list(&view, &k, None);
        assert_eq!(built.marked["a"].cipher_id, "c1");
        assert_eq!(built.marked["c"].cipher_id, "c3");
        assert_eq!(built.marked["a"].revision_date, REV);
        assert_eq!(ciphers(&s).len(), 3, "the cache is untouched");
    }

    #[test]
    fn a_queued_create_that_cannot_be_built_is_not_shown() {
        let k = keys();
        let s = sync(vec![login(&k, "c1", &[("bwss:id", "a")])]);
        let mut big = build(&s, &k, None).marked["a"].item.clone();
        big.id = "n".into();
        // A field value over the limit of a Bitwarden custom field.
        big.attributes.insert("blob".into(), "x".repeat(5_000));
        let queue = [Op::Create { id: "n".into(), collection: "login".into(), item: big }];
        let view = with_queue(&s, &queue, &k, None, &HashSet::new());
        assert_eq!(view.len(), 1);
        assert_eq!(view_labels(&view, &k), [("a".to_owned(), "name c1".to_owned())]);
    }

    #[test]
    fn api_errors_are_retried_or_refused_by_their_status() {
        let http = |status| ApiError::Http { status, message: String::new() };
        for e in [http(429), http(500), http(503), ApiError::Network("reset".into()), ApiError::NotSynced] {
            let text = e.to_string();
            assert!(matches!(map_api(e), BackendError::Unavailable(m) if m == text), "{text}");
        }
        for e in [http(400), http(401), http(404), ApiError::Protocol("odd".into())] {
            let text = e.to_string();
            assert!(matches!(map_api(e), BackendError::Rejected(m) if m == text), "{text}");
        }
    }

    #[test]
    fn a_migration_flag_that_cannot_be_set_does_not_stop_the_queue() {
        let q = queue_dir();
        // A file where the flag's directory should be: setting it fails.
        let blocker = q.flag.parent().unwrap();
        std::fs::write(blocker, b"x").unwrap();
        let user = SymmetricKey::generate();
        assert!(load_queue(&q.path, &user, &q.flag).unwrap().is_empty());
        assert!(!crate::config::flag_set(&q.flag), "not recorded, so the window stays open");
        assert_eq!(std::fs::read(blocker).unwrap(), b"x");
    }

    #[test]
    fn a_queue_that_cannot_be_read_is_never_touched() {
        let q = queue_dir();
        let user = SymmetricKey::generate();
        // A directory where the file should be: reading it fails.
        std::fs::create_dir(&q.path).unwrap();
        let e = load_queue(&q.path, &user, &q.flag).err().unwrap();
        let shown = q.path.display().to_string();
        assert!(
            matches!(&e, BackendError::Unavailable(m) if m.contains(&shown) && m.contains("left untouched")),
            "{e}"
        );
        assert!(q.path.is_dir());
        assert!(!crate::config::flag_set(&q.flag));
    }

    #[test]
    fn a_queue_of_an_older_version_is_set_aside_not_replayed() {
        let q = queue_dir();
        let user = SymmetricKey::generate();
        let old = br#"{"format":1,"ops":[]}"#;
        std::fs::write(&q.path, old).unwrap();
        assert!(load_queue(&q.path, &user, &q.flag).unwrap().is_empty());
        assert!(!q.path.exists());
        assert_eq!(std::fs::read(q.path.with_file_name("queue.json.legacy")).unwrap(), old);
    }

    #[test]
    fn an_old_queue_that_does_not_open_with_the_user_key_is_kept_aside() {
        let q = queue_dir();
        let mut file = seal(&one_op(), &SymmetricKey::generate());
        file["format"] = json!(2);
        let foreign = serde_json::to_vec(&file).unwrap();
        std::fs::write(&q.path, &foreign).unwrap();
        assert!(load_queue(&q.path, &SymmetricKey::generate(), &q.flag).unwrap().is_empty());
        assert!(!q.path.exists());
        assert_eq!(std::fs::read(&q.aside).unwrap(), foreign);
        assert!(!crate::config::flag_set(&q.flag), "the window is not closed by a queue that never opened");
    }

    #[test]
    fn a_queue_that_neither_opens_nor_moves_aside_is_left_where_it_is() {
        // The set-aside name is longer than a file name may be, so the move
        // fails on every system and for every user.
        let q = queue_dir();
        let long = q.path.with_file_name("q".repeat(250));
        let foreign = serde_json::to_vec(&seal(&one_op(), &SymmetricKey::generate())).unwrap();
        std::fs::write(&long, &foreign).unwrap();
        let e = load_queue(&long, &SymmetricKey::generate(), &q.flag).err().unwrap();
        assert!(matches!(&e, BackendError::Unavailable(m) if m.contains("left untouched")), "{e}");
        assert_eq!(std::fs::read(&long).unwrap(), foreign);
    }
}
