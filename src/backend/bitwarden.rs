//! Bitwarden backend: the keyring is every vault item marked with `bwss:id`
//! (design §3, §8).
//!
//! * Online: API-key login, `/sync`, writes straight to the server.
//! * Offline: the last sync response (still Bitwarden ciphertext) is cached,
//!   so the keyring unlocks and reads without a network; writes are queued,
//!   shown at once, and replayed in order on the next successful refresh.
//!
//! Writes go through the op runner (`runner.rs`) and dybw-core: bwss changes
//! only its own fields and the value source of an item (design §5).

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use dybw_core::api::{
    ApiError as CoreApiError, ApiKey as CoreApiKey, Client, DeviceInfo, Hub, HubOptions, ServerUrls, hub_url, run_hub,
};
use dybw_core::crypto::{AwsLcRsa, KdfParams, MarkScheme, Marker, SymmetricKey as CoreKey};
use dybw_core::ports::Storage;
use dybw_core::profile::{self, CachedSync, ProfileError, SecurityFault, UnlockWarning};
use dybw_core::sync::{Op, is_rollback};
use dybw_core::vault::fields as core_fields;
use dybw_core::vault::write::{HistoryAnswer, HistoryQuestion, NewItem, new_item};
use dybw_core::vault::{
    Keys as CoreKeys, MarkedItem as CoreItem, Namespace, Organizations, SkipReason, Uninspectable, UnmarkedCache,
    ValueSource as CoreSource, item_meta, scan_vault_with,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Mutex, watch};
use zeroize::Zeroizing;

use super::ops::{
    FORMAT as LEGACY_QUEUE_FORMAT, Loaded, QUEUE_FORMAT, QUEUE_V3, Queue, Records, header, read_formats,
    read_versioned, seal, set_aside, unseal, unseal_legacy,
};
use super::registry::{REGISTRY_ID, Registry};
use super::runner::{Effect, apply_shown, queue_lines, status_lines};
use super::worker::{Command, Worker, WorkerHandle};
use super::{AclTrust, Backend, BackendError, kdf_text};
use crate::bw::crypto::SymmetricKey;
use crate::bw::fields::{
    A_ID, A_NAME, A_URI, A_USERNAME, DERIVED, F_ACL, F_COLLECTION, F_CONTENT_TYPE, F_CREATED, F_ENCODING, F_ID, F_KIND,
    F_LABEL, F_LOCATION,
};
use crate::bw::items::parse_date;
use crate::bw::scan::{MarkedItem, ValueSource, normalize_collection};
use crate::config::{Config, Credentials, Paths};
use crate::core_ports::{
    clock::SystemClock, events::WsEvents, http::HttpPort, kdf::BlockingArgon2, random::OsRandom, storage::FileStorage,
};
use crate::fsutil::{write_json_private, write_private};
use crate::model::{Attributes, CollectionData, ItemData, LOGIN_COLLECTION, SESSION_COLLECTION, Snapshot};

const FORMAT: u64 = 2;
const TYPE_SECURE_NOTE: u64 = 2;
/// `bwss:kind` of the collection registry note.
pub(super) const KIND_COLLECTIONS: &str = "collections";
/// Cipher id of an item created by a queued op: it is not on the server yet.
pub(super) const QUEUED: &str = "";

/// Storage key of the KDF an unlock refused, for `bwss kdf accept`.
pub(crate) const KDF_OFFERED: &str = "kdf-offered";
/// Storage key of the id of the user key this device last opened (ADR 0023).
const USER_KEY_ID: &str = "user-key-id";
/// Storage key of the sealed bindings, `bwss:id` to cipher id (ADR 0019).
const BINDINGS: &str = "bindings";
/// Storage key of the rollbacks held back now, which `bwss status` lists.
pub(crate) const ROLLBACKS_HELD: &str = "rollbacks-held";
/// Storage key of the rollbacks `bwss sync --accept-rollback` accepted, for
/// the next sync only.
pub(crate) const ACCEPT_ROLLBACK: &str = "accept-rollback";
/// The core's client, as bwss runs it.
pub(crate) type CoreClient = Client<HttpPort, SystemClock>;

/// A version the server sent older than this device's copy (ADR 0019): it is
/// held back, and accepted only as exactly this cipher at this revision.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct Rollback {
    pub id: String,
    pub cipher: String,
    /// The server's (older) `revisionDate`.
    pub revision: String,
}

/// A list of rollbacks kept in `key`; none when it is missing or unreadable.
pub(crate) async fn rollbacks(storage: &impl Storage, key: &str) -> Vec<Rollback> {
    let raw = storage.load(key).await.ok().flatten();
    raw.and_then(|raw| serde_json::from_slice(&raw).ok()).unwrap_or_default()
}

/// KDF parameters as `sync.json` has always stored them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum StoredKdf {
    Pbkdf2 { iterations: u32 },
    Argon2id { iterations: u32, memory_mib: u32, parallelism: u32 },
}

impl From<KdfParams> for StoredKdf {
    fn from(k: KdfParams) -> Self {
        match k {
            KdfParams::Pbkdf2 { iterations } => Self::Pbkdf2 { iterations },
            KdfParams::Argon2id { iterations, memory_mib, parallelism } => {
                Self::Argon2id { iterations, memory_mib, parallelism }
            }
        }
    }
}

impl From<StoredKdf> for KdfParams {
    fn from(k: StoredKdf) -> Self {
        match k {
            StoredKdf::Pbkdf2 { iterations } => Self::Pbkdf2 { iterations },
            StoredKdf::Argon2id { iterations, memory_mib, parallelism } => {
                Self::Argon2id { iterations, memory_mib, parallelism }
            }
        }
    }
}

/// What an unlock refused, for `bwss kdf accept`: a weaker KDF, or (`kdf`
/// `None`) a pin that cannot be read.
#[derive(Serialize, Deserialize)]
pub(crate) struct KdfOffer {
    pub origin: String,
    kdf: Option<StoredKdf>,
}

impl KdfOffer {
    pub fn kdf(&self) -> Option<KdfParams> {
        self.kdf.map(Into::into)
    }
}

/// The offer the last refused unlock left, if any can be read.
pub(crate) async fn kdf_offer(storage: &impl Storage) -> Result<Option<KdfOffer>, dybw_core::ports::PortError> {
    Ok(storage.load(KDF_OFFERED).await?.and_then(|raw| serde_json::from_slice(&raw).ok()))
}

/// The KDF the last successful unlock ran: the core's pin holds exactly it
/// then (`kdf-pin`: `{kdf, iterations, memory, parallelism, origin}`).
// shortcut: reads the core's pin format; use the KDF from `profile::Unlocked` once the core reports it.
pub(crate) async fn ran_kdf(storage: &impl Storage) -> Option<KdfParams> {
    #[derive(Deserialize)]
    struct Pin {
        kdf: u32,
        iterations: u32,
        memory: u32,
        parallelism: u32,
    }
    let pin: Pin = serde_json::from_slice(&storage.load("kdf-pin").await.ok()??).ok()?;
    match pin.kdf {
        0 => Some(KdfParams::Pbkdf2 { iterations: pin.iterations }),
        1 => Some(KdfParams::Argon2id {
            iterations: pin.iterations,
            memory_mib: pin.memory,
            parallelism: pin.parallelism,
        }),
        _ => None,
    }
}

/// A copy of the keys, for a write that waits on the server while the
/// keyring may lock: the core's keys have no `Clone`, so they wipe on drop.
pub(crate) fn copy_keys(keys: &CoreKeys) -> CoreKeys {
    let copy = |k: &CoreKey| CoreKey::from_bytes(&k.to_bytes());
    // The bytes come from a key that exists: they always make one again.
    #[expect(clippy::expect_used, reason = "a key's own bytes always make a key")]
    let user = copy(&keys.user).expect("a key's own bytes");
    let orgs = keys.orgs.iter().filter_map(|(id, k)| copy(k).ok().map(|k| (id.clone(), k))).collect();
    CoreKeys { marker: Marker::new(&user, MarkScheme::Bwss), user, orgs, security_version: keys.security_version }
}

/// `sync.json`: the last `/sync` response, still ciphertext. The `format`
/// key is written (`CacheRef`) but not read back.
#[derive(Deserialize)]
struct Cache {
    /// The KDF of the unlock that wrote it; the core needs it offline for an
    /// account without `masterPasswordUnlock`.
    #[serde(default)]
    kdf: Option<StoredKdf>,
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
    kdf: Option<StoredKdf>,
    email: &'a str,
    revision: Option<&'a str>,
    sync: &'a Value,
}

/// `bwss:id` to the cipher id it is read from: the device's base binding
/// (ADR 0019), kept sealed in the `bindings` file.
pub(crate) type Bindings = BTreeMap<String, String>;

/// The keyring as read from one copy of the vault.
#[derive(Default)]
pub(crate) struct Built {
    pub snapshot: Snapshot,
    /// Marked items by `bwss:id`, duplicates resolved, registry excluded,
    /// held items as last read.
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
    /// The bindings after this build: every item served from the server,
    /// and every held id whose cipher is still there.
    pub bound: Bindings,
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

pub(super) fn ciphers(sync: &Value) -> &[Value] {
    sync.get("ciphers").and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn cipher_id(cipher: &Value) -> &str {
    cipher.get("id").and_then(Value::as_str).unwrap_or_default()
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
pub(super) fn read_registry(cipher: &Value, keys: &CoreKeys) -> Result<Option<Registry>, RegistryError> {
    use RegistryError::{Fields, Key, Notes, Parse};
    if cipher.get("type").and_then(Value::as_u64) != Some(TYPE_SECURE_NOTE) {
        return Ok(None);
    }
    let key = core_fields::item_key(cipher, &keys.user).map_err(|_| Key)?;
    let names = core_fields::field_names(cipher, &key).map_err(|_| Fields)?;
    let Some(i) = core_fields::first_index(&names, F_KIND) else { return Ok(None) };
    if core_fields::field_value(cipher, i, &key).map_err(|_| Fields)?.trim() != KIND_COLLECTIONS {
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

/// What `bwss status` says about a skipped item; `features` are the
/// `dybw:requires` names this bwss does not implement.
fn skip_text(reason: SkipReason, features: &[String]) -> String {
    match reason {
        SkipReason::WrongType => "its item type is not supported".into(),
        SkipReason::EncodingOnUserSource => format!("{F_ENCODING}=base64 on a value bwss does not own"),
        SkipReason::UnknownLocation => format!("unknown {F_LOCATION}"),
        SkipReason::UnknownEncoding => format!("unknown {F_ENCODING}"),
        SkipReason::InvalidId => format!("its {F_ID} is not valid"),
        SkipReason::ReservedId => format!("{REGISTRY_ID} is reserved for the collection registry"),
        SkipReason::ViewPasswordHidden => "its password is hidden from this account".into(),
        SkipReason::InvalidBase64 => "value is not valid base64".into(),
        SkipReason::NewerFormat => format!(
            "it needs what this bwss does not implement ({}): it is not used until bwss is updated",
            features.join(", ")
        ),
    }
}

pub(super) fn uninspectable_text(why: Uninspectable) -> &'static str {
    match why {
        Uninspectable::OrganizationNotRead => "organization items are not read",
        Uninspectable::OrganizationKeyMissing => "its organization key is missing",
        Uninspectable::ItemKey => "item key cannot be unwrapped",
        Uninspectable::FieldNames => "field names cannot be decrypted",
        Uninspectable::Marker => "marker cannot be decrypted",
        Uninspectable::Value => "a value cannot be decrypted",
        Uninspectable::NewerFormat => "it uses an encryption format this bwss cannot read",
        Uninspectable::Blob => "its sealed item cannot be opened",
        Uninspectable::TooLarge => "it is larger than any item bwss reads",
    }
}

/// bwss's item from the core's read (design §3). The label is `bwss:label`,
/// else the id, or the item name when `derive` is on (ADR 0015). The name,
/// username and URI are attributes only when `derive` is on; one that does
/// not decrypt is left out.
fn to_marked(m: CoreItem, keys: &CoreKeys, derive: bool) -> MarkedItem {
    let meta = item_meta(&m, keys);
    let tool = |name: &str| m.tool_fields.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str());
    let mut attributes: Attributes = m
        .attributes
        .iter()
        .filter(|(k, _)| !DERIVED.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    attributes.insert(A_ID.to_owned(), m.id.clone());
    if derive {
        for (k, v) in [(A_NAME, &meta.name), (A_USERNAME, &meta.username), (A_URI, &meta.uri)] {
            if let Some(v) = v.as_deref().filter(|v| !v.is_empty()) {
                attributes.insert(k.to_owned(), v.clone());
            }
        }
    }
    let fallback = meta.name.as_deref().filter(|n| derive && !n.is_empty()).unwrap_or(&m.id);
    let label = tool(F_LABEL).filter(|l| !l.is_empty()).unwrap_or(fallback).to_owned();
    let collection = match tool(F_COLLECTION) {
        None => LOGIN_COLLECTION.to_owned(),
        Some(c) => {
            if c.trim().eq_ignore_ascii_case(SESSION_COLLECTION) {
                tracing::warn!("{}: {F_COLLECTION}=session is memory only; the item stays in login", m.cipher_id);
            }
            normalize_collection(c)
        }
    };
    let content_type = tool(F_CONTENT_TYPE).filter(|c| !c.is_empty()).unwrap_or("text/plain").to_owned();
    let creation_date = m.creation_date.and_then(|ms| u64::try_from(ms / 1000).ok()).filter(|&d| d != 0);
    let created = tool(F_CREATED).and_then(|s| s.trim().parse().ok()).or(creation_date).unwrap_or(0);
    let acl = tool(F_ACL)
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).map(str::to_owned).collect())
        .unwrap_or_default();
    let source = match m.source {
        CoreSource::Field => ValueSource::Field,
        CoreSource::Notes => ValueSource::BwssNotes,
        CoreSource::LoginPassword => ValueSource::LoginPassword,
        CoreSource::NoteBody => ValueSource::NoteBody,
    };
    let modified = parse_date(&m.revision_date);
    MarkedItem {
        organization: m.organization_id.is_some(),
        source,
        mark: m.mark,
        creation_date,
        item: ItemData {
            id: m.id,
            collection,
            label,
            attributes,
            secret: m.value,
            content_type,
            created,
            modified,
            acl,
        },
        cipher_id: m.cipher_id,
        revision_date: m.revision_date,
    }
}

/// Builds the keyring from a copy of the vault through the core's scan
/// (design §8.2 step 4, data model §4, §7).
///
/// `cache` holds the unmarked ciphers of the last scan, so they are not
/// decrypted again. `previous` supplies the items to hold: a marked item
/// whose cipher can no longer be inspected, or whose id a skipped cipher
/// holds, stays as last read (§4, ADR 0019); one that needs a newer format
/// is not served (ADR 0020). `bound` keeps an id on the cipher this device
/// read it from (ADR 0019).
pub(crate) fn build(
    sync: &Value,
    keys: &CoreKeys,
    previous: Option<&Built>,
    cache: &mut UnmarkedCache,
    bound: &Bindings,
    derive: bool,
) -> Built {
    let report = scan_vault_with(sync, &Namespace::BWSS, keys, &Organizations::None, &|_| true, cache, bound);
    let list = ciphers(sync);
    let mut registry = Registry::default();
    let mut registry_ciphers = Vec::new();
    let mut registry_unreadable = false;
    let mut skipped = Vec::new();
    let mut newer = HashSet::new();

    for (cid, reason) in &report.skipped {
        if *reason == SkipReason::ReservedId {
            match list.iter().find(|c| cipher_id(c) == cid).map(|c| read_registry(c, keys)) {
                Some(Ok(Some(r))) => {
                    registry.merge(&r);
                    registry_ciphers.push(cid.clone());
                    continue;
                }
                Some(Err(why)) => {
                    tracing::warn!(cipher = %cid, "the collection registry cannot be read: {why}");
                    registry_unreadable = true;
                    registry_ciphers.push(cid.clone());
                    continue;
                }
                _ => {}
            }
        }
        if *reason == SkipReason::NewerFormat {
            newer.insert(cid.as_str());
        }
        let features = report.unknown_features.iter().find(|(c, _)| c == cid).map_or(&[][..], |(_, f)| f.as_slice());
        let why = format!("{cid}: {}", skip_text(*reason, features));
        if first_report(("skipped", &why)) {
            tracing::warn!("skipped: {why}");
        }
        skipped.push((cid.clone(), why));
    }

    let mut uninspectable = HashSet::new();
    for (cid, why) in &report.uninspectable {
        let text = uninspectable_text(*why);
        // Organization items are never read: not worth a warning each.
        if *why == Uninspectable::OrganizationNotRead {
            tracing::debug!("{cid}: {text}");
        } else if first_report(("uninspectable", cid, text)) {
            tracing::warn!("{cid}: {text}");
        }
        if cid.is_empty() {
            continue;
        }
        uninspectable.insert(cid.as_str());
        if let Some(p) = previous.filter(|p| p.registry_ciphers.contains(cid)) {
            registry.merge(&p.registry);
            registry_unreadable = true;
            registry_ciphers.push(cid.clone());
        }
    }

    for d in &report.duplicates {
        tracing::warn!(id = %d.id, losers = ?d.left, bound = d.bound_kept, "several items carry one bwss:id; one is used");
    }
    let duplicates = report.duplicates.into_iter().map(|d| (d.id, d.left)).collect();
    let served: HashSet<String> = report.items.iter().map(|m| m.cipher_id.clone()).collect();
    let mut marked: HashMap<String, MarkedItem> =
        report.items.into_iter().map(|m| (m.id.clone(), to_marked(m, keys, derive))).collect();
    for (id, m) in previous.map(|p| &p.marked).into_iter().flatten() {
        if marked.contains_key(id) || m.cipher_id == QUEUED {
            continue;
        }
        let ciphers = [Some(m.cipher_id.as_str()), bound.get(id).map(String::as_str)];
        let cannot_read = ciphers.iter().flatten().any(|c| uninspectable.contains(c));
        let needs_newer = ciphers.iter().flatten().any(|c| newer.contains(c));
        if (report.held_ids.contains(id) || cannot_read) && !needs_newer {
            marked.insert(id.clone(), m.clone());
        }
    }

    let mut next: Bindings =
        marked.iter().filter(|(_, m)| m.cipher_id != QUEUED).map(|(id, m)| (id.clone(), m.cipher_id.clone())).collect();
    for (id, cid) in bound {
        if !next.contains_key(id) && report.present.contains(cid) && !served.contains(cid) {
            next.insert(id.clone(), cid.clone());
        }
    }
    let shown: HashSet<&str> = marked.values().map(|m| m.cipher_id.as_str()).collect();
    let held = report.present.iter().filter(|c| !c.is_empty() && !shown.contains(c.as_str())).cloned().collect();

    let mut items: Vec<ItemData> = marked.values().map(|m| m.item.clone()).collect();
    items.sort_by(|a, b| a.id.cmp(&b.id));
    let ciphers = marked.iter().map(|(id, m)| (id.clone(), m.cipher_id.clone())).collect();
    Built {
        snapshot: Snapshot { collections: collection_list(&registry, &items), items, ciphers, held },
        marked,
        registry,
        registry_ciphers,
        registry_unreadable,
        duplicates,
        skipped,
        bound: next,
    }
}

/// ADR 0019, no rollback below the cached base: a watched cipher (`bwss:id`
/// to cipher id) that `sync` sends with an older `revisionDate` than `base`
/// has keeps the base's copy, unless `accept` lists exactly that cipher at
/// that revision. Returns what was held back and what was accepted.
fn hold_rollbacks(
    base: &Value,
    sync: &mut Value,
    watch: &Bindings,
    accept: &[Rollback],
) -> (Vec<Rollback>, Vec<Rollback>) {
    let old: HashMap<&str, &Value> = ciphers(base).iter().map(|c| (cipher_id(c), c)).collect();
    let ids: HashMap<&str, &str> = watch.iter().map(|(id, cid)| (cid.as_str(), id.as_str())).collect();
    let rev = |c: &Value| c.get("revisionDate").and_then(Value::as_str).unwrap_or_default().to_owned();
    let (mut held, mut accepted) = (Vec::new(), Vec::new());
    for c in sync.get_mut("ciphers").and_then(Value::as_array_mut).into_iter().flatten() {
        let cid = cipher_id(c).to_owned();
        if let (Some(id), Some(was)) = (ids.get(cid.as_str()), old.get(cid.as_str()))
            && is_rollback(&rev(was), &rev(c))
        {
            let rollback = Rollback { id: (*id).to_owned(), cipher: cid, revision: rev(c) };
            if accept.contains(&rollback) {
                accepted.push(rollback);
            } else {
                *c = (*was).clone();
                held.push(rollback);
            }
        }
    }
    held.sort_by(|a, b| a.id.cmp(&b.id));
    (held, accepted)
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
pub(super) fn registry_with_queue(registry: &Registry, queue: &Queue) -> Registry {
    let mut shown = registry.clone();
    for op in &queue.registry {
        shown.put(&op.collection, op.entry.clone());
    }
    shown
}

/// The ciphers with every queued item op applied, so pending writes stay
/// visible (design §8.2 step 3). Only the ciphers the ops touch are copied;
/// the rest stay borrowed from `sync`. A patch goes to the cipher `built`
/// served its item from (the bound winner, ADR 0019), or to the item's
/// queued create; a duplicate, held or newer-format cipher is never written.
pub(super) fn with_queue<'a>(
    sync: &'a Value,
    queue: &Queue,
    keys: &CoreKeys,
    folder: Option<&str>,
    built: &Built,
) -> Vec<Cow<'a, Value>> {
    let mut list: Vec<Option<Cow<'a, Value>>> = ciphers(sync).iter().map(|c| Some(Cow::Borrowed(c))).collect();
    // `bwss:id` to the place of its queued create in `list`.
    let mut created: HashMap<String, usize> = HashMap::new();
    let place = |list: &[Option<Cow<'a, Value>>], created: &HashMap<String, usize>, id: &str| {
        if let Some(&i) = created.get(id) {
            return Some(i);
        }
        let cid = built.marked.get(id).map(|m| m.cipher_id.as_str()).filter(|c| *c != QUEUED)?;
        list.iter().position(|c| c.as_deref().is_some_and(|c| cipher_id(c) == cid))
    };
    for op in &queue.ops {
        match op {
            Op::Create(item) => {
                let item = NewItem { folder_id: item.folder_id.clone().or(folder.map(str::to_owned)), ..item.clone() };
                match new_item(&item, &Namespace::BWSS, keys, &OsRandom) {
                    Ok(mut body) => {
                        body.insert("id".into(), json!(QUEUED));
                        created.insert(item.id.clone(), list.len());
                        list.push(Some(Cow::Owned(Value::Object(body))));
                    }
                    Err(e) => tracing::warn!("a queued new item cannot be shown: {e}"),
                }
            }
            Op::Patch(patch) => {
                let Some(i) = place(&list, &created, &patch.id) else { continue };
                let Some(Some(current)) = list.get(i) else { continue };
                match apply_shown(current, patch, keys) {
                    Ok(outcome) => {
                        let Some(mut body) = outcome.body else { continue };
                        body.remove("lastKnownRevisionDate");
                        for k in ["id", "revisionDate", "creationDate"] {
                            if let Some(v) = current.get(k) {
                                body.insert(k.into(), v.clone());
                            }
                        }
                        if let Some(slot) = list.get_mut(i) {
                            *slot = Some(Cow::Owned(Value::Object(body)));
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
                if let Some(i) = place(&list, &created, id)
                    && let Some(slot) = list.get_mut(i)
                {
                    *slot = None;
                    created.remove(id);
                }
            }
        }
    }
    list.into_iter().flatten().collect()
}

/// Builds the keyring from the cache with the queue applied, on top of
/// `previous`.
fn build_view(
    sync: &Value,
    queue: &Queue,
    keys: &CoreKeys,
    folder: Option<&str>,
    previous: &Built,
    cache: &mut UnmarkedCache,
    derive: bool,
) -> Built {
    let mut built = if queue.ops.is_empty() {
        build(sync, keys, Some(previous), cache, &previous.bound, derive)
    } else {
        let view: Vec<Value> =
            with_queue(sync, queue, keys, folder, previous).into_iter().map(Cow::into_owned).collect();
        build(&json!({ "ciphers": view }), keys, Some(previous), cache, &previous.bound, derive)
    };
    if !queue.registry.is_empty() {
        // `built.registry` stays the server's: only what is shown changes.
        let shown = registry_with_queue(&built.registry, queue);
        built.snapshot.collections = collection_list(&shown, &built.snapshot.items);
    }
    built
}

/// Builds the keyring for a freshly loaded cache and queue.
fn build_fresh(
    sync: &Value,
    queue: &Queue,
    keys: &CoreKeys,
    folder: Option<&str>,
    cache: &mut UnmarkedCache,
    bound: &Bindings,
    derive: bool,
) -> Built {
    let base = build(sync, keys, None, cache, bound, derive);
    if queue.is_empty() {
        return base;
    }
    build_view(sync, queue, keys, folder, &base, cache, derive)
}

/// Id of the keyring folder: the folder named `name`, lowest id first.
fn keyring_folder(sync: &Value, key: &CoreKey, name: &str) -> Option<String> {
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
pub(crate) fn queue_key(user: &CoreKey) -> CoreKey {
    user.derive_bwss("queue")
}

/// Sets the flag that closes the one-time migration window.
fn end_migration(flag: &Path) {
    if !crate::config::flag_set(flag)
        && let Err(e) = crate::config::set_flag(flag, true, b"done\n")
    {
        tracing::warn!(path = %flag.display(), "could not record that the queue moved to its key: {e}");
    }
}

/// What `load_queue` read: the queue, the write records kept with it, and
/// what `bwss status` must report.
#[derive(Default)]
pub(super) struct QueueFile {
    pub(super) queue: Queue,
    pub(super) records: Records,
    pub(super) notices: Vec<String>,
}

/// Where a format-2 or format-3 queue is kept after its migration, until a
/// flush sends or drops one of its changes.
pub(super) fn v3_backup(path: &Path) -> PathBuf {
    path.with_file_name("queue.json.v3.bak")
}

/// ADR 0023: moves the queue of the user key `old` to `queue.<old>.bak`
/// (numbered, never over an earlier one) without opening it; returns what to
/// report, with the number of changes lost when the file records it. `None`
/// when there is no queue.
fn set_aside_for_key(path: &Path, old: &str) -> Option<String> {
    // Only the characters of an id the core makes: never a path.
    let name: String = old.chars().filter(|c| c.is_ascii_alphanumeric() || "-_".contains(*c)).collect();
    let mut aside = path.with_file_name(format!("queue.{name}.bak"));
    let mut n = 1;
    while std::fs::symlink_metadata(&aside).is_ok() {
        n += 1;
        aside = path.with_file_name(format!("queue.{name}.bak.{n}"));
    }
    let file: Option<Value> = std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let count = file.as_ref().and_then(header).and_then(|(_, count)| count);
    let what = match count {
        Some(1) => "1 change".to_owned(),
        Some(n) => format!("{n} changes"),
        None => "changes".to_owned(),
    };
    match std::fs::rename(path, &aside) {
        Ok(()) => Some(format!(
            "the user key changed: {what} queued before that cannot be sent and were set aside in {}",
            aside.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => Some(format!("the user key changed, and the write queue could not be set aside: {e}")),
    }
}

/// The write records an older bwss kept beside the queue, sealed with the
/// queue key; none when there is no file or it does not open.
fn legacy_records(path: &Path, key: &CoreKey) -> Records {
    let raw = match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Records::new(),
        other => other.map_err(|e| e.to_string()),
    };
    let records = raw
        .and_then(|raw| String::from_utf8(raw).map_err(|e| e.to_string()))
        .and_then(|s| key.decrypt(s.trim()).map_err(|e| e.to_string()))
        .and_then(|json| serde_json::from_slice(&json).map_err(|e| e.to_string()));
    records.unwrap_or_else(|e| {
        tracing::warn!("what this device wrote to login passwords cannot be read ({e}): writes ask again");
        Records::new()
    })
}

/// Reads `queue.json`: format 4 under `queue_key(user)`, for the user key
/// `user_key_id`; one of another user key is set aside unopened (ADR 0023).
/// A format-3 queue (under the queue key), or a format-2 one (under the user
/// key itself, only while `migrated` is absent), is migrated once: kept as
/// `queue.json.v3.bak` and rewritten as format 4 with the write records an
/// older bwss kept in `records_path`; the flag is then set. Anything that
/// does not open is set aside, never replayed.
pub(super) fn load_queue(
    path: &Path,
    records_path: &Path,
    user: &CoreKey,
    user_key_id: &str,
    migrated: &Path,
) -> Result<QueueFile, BackendError> {
    let refuse = |e: std::io::Error| {
        unavailable(format!("cannot read the write queue {}: {e}; it is left untouched", path.display()))
    };
    let key = queue_key(user);
    let mut notices = Vec::new();
    let mut legacy = None;
    let opened = match read_formats(path, "legacy", &[LEGACY_QUEUE_FORMAT, QUEUE_V3, QUEUE_FORMAT]) {
        Loaded::Ok(v) => {
            let format = v.get("format").and_then(Value::as_u64);
            let opened = match format {
                Some(QUEUE_FORMAT) => match header(&v) {
                    Some((old, _)) if old != user_key_id => {
                        notices.extend(set_aside_for_key(path, old).inspect(|n| tracing::warn!("{n}")));
                        Ok(None)
                    }
                    _ => match unseal(&v, &key, user_key_id) {
                        Ok((queue, records)) => {
                            end_migration(migrated);
                            Ok(Some((queue, Some(records))))
                        }
                        Err(e) => Err(e.to_string()),
                    },
                },
                Some(QUEUE_V3) => unseal_legacy(&v, &key).map(|q| Some((q, None))).map_err(|e| e.to_string()),
                _ if !crate::config::flag_set(migrated) => {
                    unseal_legacy(&v, user).map(|q| Some((q, None))).map_err(|e| e.to_string())
                }
                _ => Err("it is sealed the old way, and this device already moved to the queue key".into()),
            };
            if format != Some(QUEUE_FORMAT) {
                legacy = Some(v);
            }
            match opened {
                Ok(opened) => opened,
                Err(why) => {
                    legacy = None;
                    tracing::warn!(path = %path.display(), "the write queue cannot be opened ({why}); setting it aside");
                    match set_aside(path, "unsealable") {
                        Loaded::Unreadable(e) => return Err(refuse(e)),
                        _ => None,
                    }
                }
            }
        }
        Loaded::Missing => {
            end_migration(migrated);
            None
        }
        Loaded::SetAside(to) => {
            tracing::warn!(moved_to = %to.display(), "changes queued by an older version are not replayed");
            None
        }
        Loaded::Unreadable(e) => return Err(refuse(e)),
    };
    let (queue, records) = opened.unwrap_or_default();
    let records = records.unwrap_or_else(|| legacy_records(records_path, &key));
    let file = QueueFile { queue, records, notices };
    let from_records = std::fs::symlink_metadata(records_path).is_ok();
    if legacy.is_none() && !from_records {
        return Ok(file);
    }
    // Migrates to format 4. When a step fails, the old file stays as it was
    // and the window stays open for the next unlock.
    let kept = match &legacy {
        Some(v) if !file.queue.is_empty() => write_json_private(&v3_backup(path), v),
        _ => Ok(()),
    };
    let migrated_now = kept.and_then(|()| {
        let sealed = seal(&file.queue, &file.records, &key, user_key_id, &OsRandom).map_err(std::io::Error::other)?;
        write_json_private(path, &sealed)
    });
    match migrated_now {
        Ok(()) => {
            if legacy.is_some() {
                end_migration(migrated);
            }
            if let Err(e) = std::fs::remove_file(records_path)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(path = %records_path.display(), "could not remove the old write records: {e}");
            }
        }
        Err(e) => tracing::warn!(path = %path.display(), "could not move the write queue to format 4: {e}"),
    }
    Ok(file)
}

pub(super) struct Unlocked {
    /// The keys dybw-core opened.
    pub(super) core_keys: CoreKeys,
    kdf: Option<KdfParams>,
    /// The server's copy of the vault, as cached; queued ops are not in it.
    pub(super) sync: Value,
    /// Raw account revision date of `sync`, when known.
    revision: Option<String>,
    /// The keyring: `sync` with the queue applied.
    pub(super) built: Built,
    /// Whether `built` was made with derived attributes on (ADR 0015).
    derive: bool,
    /// The core's scan cache: the unmarked ciphers of the last build.
    cache: UnmarkedCache,
    pub(super) keyring_folder: Option<String>,
    /// What `bwss status` reports about this unlock.
    notices: Vec<String>,
    /// Ids the server sent older than the cached copy, which is kept (ADR 0019).
    pub(super) rollbacks: Vec<Rollback>,
    /// What this device wrote to login passwords, by `bwss:id` (ADR 0016);
    /// kept in the queue file.
    pub(super) records: Records,
    /// The id of the user key, which the queue file records (ADR 0023).
    pub(super) user_key_id: String,
    /// The history questions queued changes wait on, from the last flush.
    pub(super) questions: Vec<(String, HistoryQuestion)>,
    /// Queued changes whose own cipher this bwss can never read.
    pub(super) stuck: Vec<(String, Uninspectable)>,
}

pub(crate) struct Bitwarden {
    email: String,
    /// Name of the keyring folder.
    pub(super) root: String,
    /// The core's client, logged in and synced; `None` until then, and
    /// after a lock or an ended session.
    pub(super) client: Mutex<Option<CoreClient>>,
    key: CoreApiKey,
    pub(super) state: Mutex<Option<Unlocked>>,
    cache_path: PathBuf,
    queue_path: PathBuf,
    /// Device flag: the queue moved to the queue key, so a queue under the
    /// user key is never opened again.
    queue_migrated: PathBuf,
    /// Queued ops; loaded at unlock (it is sealed with the queue key) and
    /// dropped at lock. Lock order: `queue`, then `state`.
    pub(super) queue: Mutex<Queue>,
    /// Bumped by every `lock`: an unlock that started before one never
    /// installs its keys.
    lock_generation: AtomicU64,
    /// Where dybw-core's client goes, and as which device.
    pub(super) urls: ServerUrls,
    device: DeviceInfo,
    /// dybw-core's device state: the KDF pin, the security version, the user key id.
    storage: FileStorage,
    /// The sealed `BINDINGS` file, written from the worker without awaiting.
    bindings_path: PathBuf,
    /// Where an older bwss kept the write records (ADR 0016) beside the
    /// queue: read once, then kept in the queue file.
    records_path: PathBuf,
    /// An accept record a sync used but could not remove: never used again.
    spent_accept: std::sync::Mutex<Option<Vec<Rollback>>>,
    acl_confirmed: PathBuf,
    /// The device flag `bwss derive on` (ADR 0015), read at every build.
    derive_on: PathBuf,
    /// Present while `derive_on` was carried over from `bwss index derived`.
    derive_carried: PathBuf,
    /// Whether to follow the notifications hub (`[bwss] notifications`).
    notifications: bool,
    /// Told when the hub reports a change made elsewhere; the daemon refreshes.
    pub(super) changes: watch::Sender<()>,
    /// The hub task of this unlock, stopped by `lock`.
    pub(super) hub: std::sync::Mutex<Option<tokio::task::AbortHandle>>,
}

/// The online half of an unlock.
#[expect(
    clippy::large_enum_variant,
    reason = "one per unlock; a Box would leave a copy of the keys unwiped on the heap"
)]
enum Online {
    Opened(profile::Unlocked, Option<String>, CoreClient),
    /// The network is down: the offline copy may be used.
    Unreachable(String),
}

fn unavailable(e: impl std::fmt::Display) -> BackendError {
    BackendError::Unavailable(e.to_string())
}

fn map_core_api(e: CoreApiError) -> BackendError {
    if e.is_transient() { BackendError::Unavailable(e.to_string()) } else { BackendError::Rejected(e.to_string()) }
}

/// An unlock the core refused, with the command that answers it.
fn map_profile(e: ProfileError) -> BackendError {
    match e {
        ProfileError::WrongPassword => BackendError::WrongPassword,
        ProfileError::Api(e) => map_core_api(e),
        e @ ProfileError::Port(_) => unavailable(e),
        ProfileError::KdfWeakened { pinned, offered, kdf_source } => {
            BackendError::KdfWeakened { pinned, offered, kdf_source }
        }
        ProfileError::KdfPinUnreadable => BackendError::KdfPinUnreadable,
        ProfileError::SecurityDowngrade { seen, offered } => BackendError::SecurityDowngrade { seen, offered },
        ProfileError::SecurityState(SecurityFault::StoredUnreadable) => BackendError::SecurityState(
            "the security state version saved on this device is unreadable: `bwss security accept 0` forgets it, \
             and the next unlock saves the account's version again"
                .into(),
        ),
        ProfileError::SecurityState(fault) => BackendError::SecurityState(format!(
            "the account's security state {fault}: check the account in the web vault"
        )),
        ProfileError::IncompleteUnlockData => BackendError::Rejected(
            "the account sent no usable unlock data, or the offline copy lacks its KDF: unlock online, or check \
             the account in the web vault"
                .into(),
        ),
        e @ ProfileError::Crypto(_) => BackendError::Rejected(e.to_string()),
    }
}

impl Bitwarden {
    pub fn new(config: &Config, creds: Credentials, paths: &Paths) -> anyhow::Result<Self> {
        let profile = config.profile.as_deref().ok_or_else(|| anyhow::anyhow!("no profile to serve"))?;
        let core_urls = dybw_core::api::resolve_server_urls(&config.server_url)?;
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
        Ok(Bitwarden {
            email: config.email.clone(),
            root: config.folder.trim_matches('/').to_owned(),
            client: Mutex::new(None),
            key: CoreApiKey {
                origin: creds.identity_origin,
                client_id: creds.client_id,
                client_secret: creds.client_secret,
            },
            state: Mutex::new(None),
            cache_path: paths.cache.join("sync.json"),
            queue_path,
            queue_migrated: paths.queue_key_migrated(),
            queue: Mutex::new(Queue::default()),
            lock_generation: AtomicU64::new(0),
            urls: core_urls,
            // As bwss's own client announces itself.
            device: DeviceInfo {
                identifier: device_id,
                name: "bwss".into(),
                device_type: 8,
                client_name: "bwss".into(),
                client_version: env!("CARGO_PKG_VERSION").into(),
            },
            storage: FileStorage::new(paths, profile),
            bindings_path: paths.tool_state.join("core").join(BINDINGS),
            records_path: paths.state.join("write-records"),
            spent_accept: std::sync::Mutex::new(None),
            acl_confirmed: paths.acl_confirmed(),
            derive_on: paths.derive_on(),
            derive_carried: paths.derive_carried(),
            notifications: config.notifications,
            changes: watch::channel(()).0,
            hub: std::sync::Mutex::new(None),
        })
    }

    /// Follows the server's notifications hub until the next lock (owner's
    /// decision 3), on the worker's `LocalSet`. The core's [`Hub`] decides
    /// the reconnect timing; the periodic refresh runs either way.
    pub(super) fn start_hub(self: &std::rc::Rc<Self>) {
        if !self.notifications {
            return;
        }
        let vault = self.clone();
        let task = tokio::task::spawn_local(async move { vault.follow_hub().await });
        if let Some(old) = self.hub.lock().ok().and_then(|mut h| h.replace(task.abort_handle())) {
            old.abort();
        }
    }

    async fn follow_hub(&self) {
        // The URL carries the access token: it is never logged.
        // shortcut: an expired token is renewed by the next periodic refresh, not here; until then the hub's
        // reconnects back off. Renew here if that gap shows in practice.
        let url = async || {
            let client = self.client.lock().await;
            Some(hub_url(&self.urls.notifications, client.as_ref()?.access_token()?))
        };
        let mut hub = Hub::new(HubOptions::default(), self.device.identifier.clone());
        run_hub(&WsEvents, &SystemClock, url, &mut hub, || self.changes.send_replace(()), || false).await;
    }

    /// A client of the server, not logged in yet.
    fn new_client(&self) -> Result<CoreClient, CoreApiError> {
        let http = HttpPort::new().map_err(|e| CoreApiError::Network(e.0))?;
        Client::new(http, SystemClock, self.urls.clone(), self.device.clone())
    }

    /// `profile::unlock` with bwss's ports. A network that is down is not
    /// an error here: the caller falls back to the offline copy.
    async fn open_online(&self, password: Zeroizing<String>) -> Result<Online, BackendError> {
        let mut client = self.new_client().map_err(map_core_api)?;
        // The revision is read before `/sync`, as bwss always did: a change
        // between the two is then seen by the next refresh.
        let revision = match client.login(&self.key).await {
            Ok(()) => client.revision_date().await.ok(),
            Err(e) if e.is_transient() => return Ok(Online::Unreachable(e.to_string())),
            Err(e) => return Err(map_core_api(e)),
        };
        let (ns, orgs) = (&Namespace::BWSS, &Organizations::None);
        let opened = profile::unlock(
            &mut client,
            &self.storage,
            &self.key,
            &self.email,
            password,
            &BlockingArgon2,
            &AwsLcRsa,
            ns,
            orgs,
        )
        .await;
        match opened {
            Ok(unlocked) => Ok(Online::Opened(unlocked, revision, client)),
            Err(ProfileError::Api(e)) if e.is_transient() => Ok(Online::Unreachable(e.to_string())),
            Err(e) => Err(self.refused(e).await),
        }
    }

    /// Opens the user key online, else from the offline copy when the network
    /// is down: the unlocked profile, the account revision and whether it came
    /// from the copy.
    async fn open(
        &self,
        password: &str,
    ) -> Result<(profile::Unlocked, Option<String>, Option<CoreClient>), BackendError> {
        let password = Zeroizing::new(password.to_owned());
        let why = match self.open_online(password.clone()).await? {
            Online::Opened(unlocked, revision, client) => return Ok((unlocked, revision, Some(client))),
            Online::Unreachable(why) => why,
        };
        let Cache { kdf, email, revision, sync } = load_cache(&self.cache_path, &self.email)?
            .ok_or_else(|| unavailable(format!("Bitwarden is unreachable and there is no offline copy yet: {why}")))?;
        tracing::info!("Bitwarden unreachable; unlocking from the offline copy");
        let cached = CachedSync { sync, prelogin_kdf: kdf.map(Into::into), email };
        let (ns, orgs) = (&Namespace::BWSS, &Organizations::None);
        let origin = &self.key.origin;
        match profile::unlock_cached(cached, &self.storage, origin, password, &BlockingArgon2, &AwsLcRsa, ns, orgs)
            .await
        {
            Ok(unlocked) => Ok((unlocked, revision, None)),
            Err(e) => Err(self.refused(e).await),
        }
    }

    /// Maps a refused unlock, and keeps what `bwss kdf accept` needs to answer it.
    async fn refused(&self, e: ProfileError) -> BackendError {
        let kdf = match &e {
            ProfileError::KdfWeakened { offered, .. } => Some(Some(StoredKdf::from(*offered))),
            ProfileError::KdfPinUnreadable => Some(None),
            _ => None,
        };
        if let Some(kdf) = kdf {
            // Numbers and text: it always serializes.
            let offer = serde_json::to_vec(&KdfOffer { origin: self.key.origin.clone(), kdf }).unwrap_or_default();
            if let Err(e) = self.storage.save(KDF_OFFERED, &offer).await {
                tracing::warn!("could not keep the offered KDF for `bwss kdf accept`: {e}");
            }
        }
        map_profile(e)
    }

    /// ADR 0023: what the old user key sealed cannot be opened with a new one.
    /// When the key changed, the queue is set aside and the ACL confirmations
    /// are dropped; returns what to report.
    async fn check_user_key(&self, id: &str) -> Vec<String> {
        let saved = self.storage.load(USER_KEY_ID).await.ok().flatten();
        let saved = saved.as_deref().map(String::from_utf8_lossy);
        let old = saved.as_deref().map(str::trim).filter(|old| !old.is_empty());
        let mut notices = Vec::new();
        if let Some(old) = old.filter(|old| *old != id) {
            notices.extend(set_aside_for_key(&self.queue_path, old));
            match std::fs::remove_file(&self.acl_confirmed) {
                Ok(()) => notices.push("the user key changed: every ACL line is asked again on this device".into()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    notices.push(format!("the user key changed, and the ACL confirmations could not be reset: {e}"))
                }
            }
        }
        if old != Some(id)
            && let Err(e) = self.storage.save(USER_KEY_ID, id.as_bytes()).await
        {
            tracing::warn!("could not record the id of the user key: {e}");
        }
        for notice in &notices {
            tracing::warn!("{notice}");
        }
        notices
    }

    /// `/accounts/revision-date` (when it answers), then `/sync`. A client
    /// that is not logged in logs in first; the client is kept once synced.
    async fn fetch(&self) -> Result<(Option<String>, Value), CoreApiError> {
        let mut guard = self.client.lock().await;
        let synced = guard.is_some();
        let mut client = match guard.take() {
            Some(client) => client,
            None => {
                let mut client = self.new_client()?;
                client.login(&self.key).await?;
                client
            }
        };
        let revision = client.revision_date().await.ok();
        match client.sync().await {
            Ok(sync) => {
                *guard = Some(client);
                Ok((revision, sync))
            }
            Err(e) => {
                // An ended session logs in again next time; any other failure
                // keeps a client that was synced before.
                let ended = matches!(e, CoreApiError::Http { status: 401, .. } | CoreApiError::NotLoggedIn);
                if synced && !ended {
                    *guard = Some(client);
                }
                Err(e)
            }
        }
    }

    /// Whether writes can go to the server now: logged in and synced.
    pub(super) async fn can_write(&self) -> bool {
        self.client.lock().await.is_some()
    }

    fn save_cache(&self, state: &Unlocked) {
        let cache = CacheRef {
            format: FORMAT,
            kdf: state.kdf.map(StoredKdf::from),
            email: &self.email,
            revision: state.revision.as_deref(),
            sync: &state.sync,
        };
        if let Err(e) = write_json_private(&self.cache_path, &cache) {
            tracing::warn!("could not write the offline cache: {e}");
        }
    }

    /// Writes the queue file (format 4): `queue` and `records`, sealed with
    /// `key`, the queue key of the user key `user_key_id`.
    pub(super) fn save_queue(
        &self,
        queue: &Queue,
        records: &Records,
        key: &CoreKey,
        user_key_id: &str,
    ) -> std::io::Result<()> {
        let saved = seal(queue, records, key, user_key_id, &OsRandom)
            .map_err(std::io::Error::other)
            .and_then(|file| write_json_private(&self.queue_path, &file));
        if let Err(e) = &saved {
            tracing::warn!("could not write the offline queue: {e}");
        }
        saved
    }

    /// `save_queue` with the records and the keys of `state`. A write record
    /// that is not kept makes the next write to that login ask again.
    pub(super) fn keep_queue(&self, queue: &Queue, state: &Unlocked) -> std::io::Result<()> {
        self.save_queue(queue, &state.records, &queue_key(&state.core_keys.user), &state.user_key_id)
    }

    /// Drops `queue.json.v3.bak` once a flush has sent or dropped a change
    /// of the migrated queue: the old file would replay it.
    pub(super) fn drop_v3_backup(&self) {
        match std::fs::remove_file(v3_backup(&self.queue_path)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                tracing::warn!("could not remove the queue kept from before format 4: {e}");
            }
            _ => {}
        }
    }

    /// Rebuilds the keyring after the cache or the queue changed.
    pub(super) fn rebuild(&self, state: &mut Unlocked, queue: &Queue) {
        let derive = crate::config::flag_set(&self.derive_on);
        let built = build_view(
            &state.sync,
            queue,
            &state.core_keys,
            state.keyring_folder.as_deref(),
            &state.built,
            &mut state.cache,
            derive,
        );
        if built.bound != state.built.bound {
            self.save_bindings(&state.core_keys.user, &built.bound);
        }
        state.built = built;
        state.derive = derive;
    }

    /// The key the bindings are sealed with: a purpose of their own, so the
    /// queue file can never be read as bindings, nor bindings as a queue.
    fn bindings_key(user: &CoreKey) -> CoreKey {
        user.derive_bwss("bindings")
    }

    /// Keeps the bindings, sealed, for the next unlock. A failure is logged:
    /// the next build writes them again.
    fn save_bindings(&self, user: &CoreKey, bound: &Bindings) {
        // Strings only: it always serializes.
        let json = Zeroizing::new(serde_json::to_vec(bound).unwrap_or_default());
        let saved = Self::bindings_key(user)
            .encrypt(&json, &OsRandom)
            .map_err(|e| e.to_string())
            .and_then(|sealed| write_private(&self.bindings_path, sealed.as_bytes()).map_err(|e| e.to_string()));
        if let Err(e) = saved {
            tracing::warn!("could not keep which cipher each item is read from: {e}");
        }
    }

    /// The bindings the last build kept: `Ok(None)` when there is no file,
    /// `Err` when it does not open. Bindings an older bwss sealed with the
    /// queue key are read once and sealed again with their own key; only a
    /// non-empty map counts, so no other file of that key passes for them.
    fn load_bindings(&self, user: &CoreKey) -> Result<Option<Bindings>, String> {
        let sealed = match std::fs::read(&self.bindings_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            other => {
                other.map_err(|e| e.to_string()).and_then(|raw| String::from_utf8(raw).map_err(|e| e.to_string()))?
            }
        };
        let open = |key: &CoreKey| -> Result<Bindings, String> {
            let json = key.decrypt(sealed.trim()).map_err(|e| e.to_string())?;
            serde_json::from_slice(&json).map_err(|e| e.to_string())
        };
        match open(&Self::bindings_key(user)) {
            Ok(bound) => Ok(Some(bound)),
            Err(why) => match open(&queue_key(user)) {
                Ok(bound) if !bound.is_empty() => {
                    self.save_bindings(user, &bound);
                    Ok(Some(bound))
                }
                _ => Err(why),
            },
        }
    }

    /// Keeps the rollbacks held back now, for `bwss sync --accept-rollback`.
    async fn keep_held_rollbacks(&self, held: &[Rollback]) {
        let kept = if held.is_empty() {
            self.storage.remove(ROLLBACKS_HELD).await
        } else {
            // Strings only: it always serializes.
            self.storage.save(ROLLBACKS_HELD, &serde_json::to_vec(held).unwrap_or_default()).await
        };
        if let Err(e) = kept {
            tracing::warn!("could not keep the list of rollbacks held back: {e}");
        }
    }

    /// The accept record was used by a sync, or the keyring locked or
    /// unlocked: it is never applied again. One that cannot be removed is
    /// remembered as spent, and the returned note says so.
    async fn drop_accepted_rollbacks(&self) -> Option<String> {
        let record = rollbacks(&self.storage, ACCEPT_ROLLBACK).await;
        let e = self.storage.remove(ACCEPT_ROLLBACK).await.err()?;
        if let Ok(mut spent) = self.spent_accept.lock() {
            *spent = Some(record);
        }
        let note = format!("the accepted rollbacks could not be cleared ({e}); they are not used again");
        tracing::warn!("{note}");
        Some(note)
    }

    /// Records what the server did in the cache, so later edits build on it.
    pub(super) fn absorb(&self, state: &mut Unlocked, queue: &Queue, effect: Effect) {
        if let Some(list) = state.sync.get_mut("ciphers").and_then(Value::as_array_mut) {
            match effect {
                Effect::Nothing => {}
                Effect::Trashed(gone) => list.retain(|c| c.get("id").and_then(Value::as_str) != Some(&gone)),
                Effect::Saved(server) => {
                    let c = dybw_core::api::normalize_keys(server);
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
        self.rebuild(state, queue);
    }

    /// Keeps the queue on disk and shows it.
    pub(super) async fn queue_changed(&self, queue: &Queue) -> Result<(), BackendError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        // Logged in `save_queue`; the change is already in memory.
        let _ = self.keep_queue(queue, state);
        self.rebuild(state, queue);
        Ok(())
    }

    /// Reads the vault again and shows it with `queue`; a rollback is held
    /// back unless `accept` lists it (ADR 0019). Returns what is held back.
    pub(super) async fn pull(&self, queue: &Queue, accept: &[Rollback]) -> Result<Vec<Rollback>, BackendError> {
        let (revision, mut sync) = self.fetch().await.map_err(map_core_api)?;
        let held = {
            let mut guard = self.state.lock().await;
            let state = guard.as_mut().ok_or(BackendError::Locked)?;
            let (held, accepted) = hold_rollbacks(&state.sync, &mut sync, &state.built.bound, accept);
            for r in &accepted {
                tracing::warn!(id = %r.id, cipher = %r.cipher, revision = %r.revision, "rollback accepted");
            }
            state.rollbacks = held;
            report_rollbacks(&state.rollbacks);
            state.keyring_folder = keyring_folder(&sync, &state.core_keys.user, &self.root);
            state.sync = sync;
            state.revision = revision;
            self.save_cache(state);
            self.rebuild(state, queue);
            state.rollbacks.clone()
        };
        self.keep_held_rollbacks(&held).await;
        Ok(held)
    }
}

/// The [`Backend`] operations, run by the worker: their futures await the
/// core's, which are not `Send`.
impl Bitwarden {
    pub(crate) async fn unlock(&self, password: &str) -> Result<Snapshot, BackendError> {
        let generation = self.lock_generation.load(Ordering::SeqCst);
        let (unlocked, revision, client) = self.open(password).await?;
        let from_cache = client.is_none();
        let user_key_id = unlocked.user_key_id();
        let mut notices = self.check_user_key(&user_key_id).await;
        for UnlockWarning::KdfBelowFloor { params, kdf_source } in &unlocked.warnings {
            let note = format!(
                "the KDF is below ADR 0017's floor ({}, {kdf_source}): strengthen it in the web vault",
                kdf_text(params)
            );
            tracing::warn!("{note}");
            notices.push(note);
        }
        // Answered, or no longer asked.
        let _ = self.storage.remove(KDF_OFFERED).await;
        let kdf = ran_kdf(&self.storage).await;
        let profile::Unlocked { keys: core_keys, mut sync, .. } = unlocked;
        // Accepted for an unlocked keyring only: one left by an earlier session is never applied.
        notices.extend(self.drop_accepted_rollbacks().await);
        // The offline copy is the base: the server may not go below it.
        let base = if from_cache { None } else { load_cache(&self.cache_path, &self.email).ok().flatten() };
        let lost = match self.load_bindings(&core_keys.user) {
            Ok(Some(bound)) => Ok(bound),
            Ok(None) if base.is_none() && !from_cache => Ok(Bindings::new()),
            Ok(None) => Err("are missing".to_owned()),
            Err(e) => Err(format!("cannot be read ({e})")),
        };
        let bound = match lost {
            Ok(bound) => bound,
            Err(why) => {
                // Read again from the offline copy, so neither check is off.
                let note = format!(
                    "the saved item bindings {why}: duplicate and rollback protection rests on the offline copy \
                     until the next build rewrites them"
                );
                tracing::warn!("{note}");
                notices.push(note);
                let copy = base.as_ref().map_or(&sync, |b| &b.sync);
                build(copy, &core_keys, None, &mut UnmarkedCache::default(), &Bindings::new(), false).bound
            }
        };
        let rollbacks = base.map(|base| hold_rollbacks(&base.sync, &mut sync, &bound, &[]).0).unwrap_or_default();
        report_rollbacks(&rollbacks);
        self.keep_held_rollbacks(&rollbacks).await;

        let mut queue = self.queue.lock().await;
        let file =
            load_queue(&self.queue_path, &self.records_path, &core_keys.user, &user_key_id, &self.queue_migrated)?;
        *queue = file.queue;
        let records = file.records;
        notices.extend(file.notices);
        let folder = keyring_folder(&sync, &core_keys.user, &self.root);
        let mut cache = UnmarkedCache::default();
        let derive = crate::config::flag_set(&self.derive_on);
        let built = build_fresh(&sync, &queue, &core_keys, folder.as_deref(), &mut cache, &bound, derive);
        if built.bound != bound {
            self.save_bindings(&core_keys.user, &built.bound);
        }
        let state = Unlocked {
            core_keys,
            kdf,
            sync,
            revision,
            built,
            derive,
            cache,
            keyring_folder: folder,
            notices,
            rollbacks,
            records,
            user_key_id,
            questions: Vec::new(),
            stuck: Vec::new(),
        };
        if !from_cache {
            self.save_cache(&state);
        }
        let mut guard = self.state.lock().await;
        if self.lock_generation.load(Ordering::SeqCst) != generation {
            // A lock came in while this unlock waited: it wins, and the keys
            // derived here are dropped.
            queue.clear();
            return Err(BackendError::Locked);
        }
        *guard = Some(state);
        // Under the state lock, so a lock that follows drops this client too.
        *self.client.lock().await = client;
        drop(guard);
        drop(queue);

        if !from_cache && let Err(e) = self.flush_queue().await {
            tracing::info!("queued changes stay queued: {e}");
        }
        let guard = self.state.lock().await;
        Ok(guard.as_ref().ok_or(BackendError::Locked)?.built.snapshot.clone())
    }

    pub(crate) async fn lock(&self) {
        self.lock_generation.fetch_add(1, Ordering::SeqCst);
        if let Some(hub) = self.hub.lock().ok().and_then(|mut h| h.take()) {
            hub.abort();
        }
        *self.state.lock().await = None;
        // A flush in progress clears the queue itself when it finds the
        // keyring locked; never wait for its network calls here.
        if let Ok(mut queue) = self.queue.try_lock() {
            queue.clear();
        }
        // Waits for a request in flight, then logs out.
        *self.client.lock().await = None;
        // Accepted for this session only.
        let _ = self.drop_accepted_rollbacks().await;
    }

    pub(crate) async fn refresh(&self) -> Result<Option<Snapshot>, BackendError> {
        let before = {
            let guard = self.state.lock().await;
            guard.as_ref().ok_or(BackendError::Locked)?.built.snapshot.clone()
        };
        // `bwss derive on|off` shows at once, not at the next change on the server.
        {
            let queue = self.queue.lock().await;
            if let Some(state) = self.state.lock().await.as_mut()
                && state.derive != crate::config::flag_set(&self.derive_on)
            {
                self.rebuild(state, &queue);
            }
        }
        // Before the first `/sync` of this session (offline unlock, or an
        // ended session), writes cannot name their owner: sync first, flush after.
        let synced = self.can_write().await;
        let mut accept = rollbacks(&self.storage, ACCEPT_ROLLBACK).await;
        let spent = self.spent_accept.lock().map(|s| s.as_ref() == Some(&accept)).unwrap_or(true);
        if spent {
            accept.clear();
        }
        let accepting = !accept.is_empty();
        // An accepted rollback always pulls, so what was held back is taken.
        if synced && !accepting {
            if let Err(e) = self.flush_queue().await {
                tracing::info!("queued changes stay queued: {e}");
            }
            let revision = match self.client.lock().await.as_mut() {
                Some(client) => client.revision_date().await.ok(),
                None => None,
            };
            let guard = self.state.lock().await;
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            if revision.is_some() && revision == state.revision {
                return Ok((state.built.snapshot != before).then(|| state.built.snapshot.clone()));
            }
        }
        {
            let queue = self.queue.lock().await;
            self.pull(&queue, &accept).await?;
        }
        if accepting
            && let Some(note) = self.drop_accepted_rollbacks().await
            && let Some(state) = self.state.lock().await.as_mut()
        {
            state.notices.push(note);
        }
        if let Err(e) = self.flush_queue().await {
            tracing::info!("queued changes stay queued: {e}");
        }
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;
        Ok((state.built.snapshot != before).then(|| state.built.snapshot.clone()))
    }

    pub(crate) async fn create_collection(&self, label: &str) -> Result<CollectionData, BackendError> {
        let mut queue = self.queue.lock().await;
        let result = self.create_collection_locked(&mut queue, label).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    pub(crate) async fn delete_collection(&self, id: &str, items: &[String]) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        let result = self.delete_collection_locked(&mut queue, id, items).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    #[cfg(test)]
    pub(crate) async fn put_item(&self, item: &ItemData) -> Result<(), BackendError> {
        self.put_item_answered(item, None).await
    }

    /// `put_item` with the user's answer to the history question an earlier
    /// try of the same write asked (ADR 0016).
    pub(crate) async fn put_item_answered(
        &self,
        item: &ItemData,
        answer: Option<(HistoryQuestion, HistoryAnswer)>,
    ) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        let result = self.put_locked(&mut queue, item, answer).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    /// The history question the queued change of `id` waits on (ADR 0016).
    pub(crate) async fn queued_question(&self, id: &str) -> Result<Option<HistoryQuestion>, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;
        Ok(state.questions.iter().find(|(i, _)| i == id).map(|(_, q)| *q))
    }

    /// Puts the user's answer, which the daemon confirmed, on the queued
    /// change of `id`; `None` cancels its value change (ADR 0016).
    pub(crate) async fn answer_queued(
        &self,
        id: &str,
        question: HistoryQuestion,
        answer: Option<HistoryAnswer>,
    ) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        let result = self.answer_locked(&mut queue, id, question, answer).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    pub(crate) async fn delete_item(&self, item: &ItemData) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        let result = self.delete_locked(&mut queue, &item.id).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    pub(crate) async fn acl_trust(&self) -> Result<AclTrust, BackendError> {
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or(BackendError::Locked)?;
        // ADR 0023: from the core's key, legacy or COSE; for a legacy key the
        // same bytes as bwss's own derivation.
        let key = state.core_keys.user.derive_bwss("acl-confirm").to_bytes();
        Ok(AclTrust::PerDevice(SymmetricKey::from_bytes(&key).map_err(|e| BackendError::Rejected(e.to_string()))?))
    }

    pub(crate) async fn describe(&self) -> String {
        let queue = self.queue.lock().await;
        let mut out = format!(
            "Bitwarden {} ({}), folder \"{}\", {} queued change(s)",
            self.email,
            self.urls.identity,
            self.root,
            queue.len()
        );
        if let Some(state) = self.state.lock().await.as_ref() {
            let rollbacks = (!state.rollbacks.is_empty()).then(|| rollback_text(&state.rollbacks));
            let lines = status_lines(&state.built, crate::config::flag_set(&self.derive_on))
                .into_iter()
                .chain(rollbacks)
                .chain(queue_lines(state, &queue))
                .chain(state.notices.iter().cloned());
            let carried = crate::config::flag_set(&self.derive_carried).then(|| CARRIED_NOTICE.to_owned());
            for line in lines.chain(carried) {
                out.push('\n');
                out.push_str(&line);
            }
        }
        out
    }
}

/// `bwss status` until the user runs `bwss derive on` or `off` themselves.
const CARRIED_NOTICE: &str = "derived attributes (name, username, URI) are now visible on the session bus because the \
     old `bwss index derived` setting was carried over; `bwss derive off` hides them";

/// What `bwss status` says about items the server sent older (ADR 0019).
fn rollback_text(held: &[Rollback]) -> String {
    let ids: Vec<&str> = held.iter().map(|r| r.id.as_str()).collect();
    format!(
        "older on the server than the copy this device has, which is kept: {}; `bwss sync --accept-rollback` takes \
         the server's versions",
        ids.join(", ")
    )
}

fn report_rollbacks(ids: &[Rollback]) {
    if !ids.is_empty() && first_report(("rollback", ids)) {
        tracing::warn!("{}", rollback_text(ids));
    }
}

/// What the daemon sees: a handle on the worker thread that owns the vault.
pub struct BitwardenBackend(WorkerHandle, watch::Receiver<()>);

impl BitwardenBackend {
    pub fn new(config: &Config, creds: Credentials, paths: &Paths) -> anyhow::Result<Self> {
        let (config, paths) = (config.clone(), paths.clone());
        let (changes, follow) = watch::channel(());
        let init = move || Ok(Bitwarden { changes, ..Bitwarden::new(&config, creds, &paths)? });
        Worker::spawn(init).map(|worker| Self(worker, follow))
    }

    /// Marked changed whenever the notifications hub reports a change made
    /// elsewhere while unlocked.
    pub fn changes(&self) -> watch::Receiver<()> {
        self.1.clone()
    }

    #[cfg(test)]
    pub(super) async fn panic_for_test(&self) -> Result<(), BackendError> {
        self.0.call(Command::Panic).await
    }

    #[cfg(test)]
    pub(super) fn stopped_for_test() -> Self {
        Self(WorkerHandle::stopped(), watch::channel(()).1)
    }
}

#[async_trait]
impl Backend for BitwardenBackend {
    async fn unlock(&self, password: &str) -> Result<Snapshot, BackendError> {
        self.0.call(|r| Command::Unlock(Zeroizing::new(password.to_owned()), r)).await?
    }

    async fn lock(&self) {
        // A worker that is gone holds no keys.
        let _ = self.0.call(Command::Lock).await;
    }

    async fn refresh(&self) -> Result<Option<Snapshot>, BackendError> {
        self.0.call(Command::Refresh).await?
    }

    async fn create_collection(&self, label: &str) -> Result<CollectionData, BackendError> {
        self.0.call(|r| Command::CreateCollection(label.to_owned(), r)).await?
    }

    async fn delete_collection(&self, id: &str, items: &[String]) -> Result<(), BackendError> {
        self.0.call(|r| Command::DeleteCollection(id.to_owned(), items.to_vec(), r)).await?
    }

    async fn put_item(&self, item: &ItemData) -> Result<(), BackendError> {
        self.0.call(|r| Command::PutItem(item.clone(), None, r)).await?
    }

    async fn put_item_answered(
        &self,
        item: &ItemData,
        answer: (HistoryQuestion, HistoryAnswer),
    ) -> Result<(), BackendError> {
        self.0.call(|r| Command::PutItem(item.clone(), Some(answer), r)).await?
    }

    async fn queued_question(&self, id: &str) -> Result<Option<HistoryQuestion>, BackendError> {
        self.0.call(|r| Command::QueuedQuestion(id.to_owned(), r)).await?
    }

    async fn answer_queued(
        &self,
        id: &str,
        question: HistoryQuestion,
        answer: Option<HistoryAnswer>,
    ) -> Result<(), BackendError> {
        self.0.call(|r| Command::AnswerQueued(id.to_owned(), question, answer, r)).await?
    }

    async fn delete_item(&self, item: &ItemData) -> Result<(), BackendError> {
        self.0.call(|r| Command::DeleteItem(item.clone(), r)).await?
    }

    async fn acl_trust(&self) -> Result<AclTrust, BackendError> {
        self.0.call(Command::AclTrust).await?
    }

    async fn describe(&self) -> String {
        self.0.call(Command::Describe).await.unwrap_or_else(|e| e.to_string())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::backend::ops::{new_item_of, target};
    use crate::bw::scan::Keys;
    use dybw_core::vault::write::{FieldSet, Patch, ValueChange};

    const REV: &str = "2026-01-02T03:04:05Z";

    fn keys() -> Keys {
        let user = SymmetricKey::generate();
        Keys { mark: user.derive("value-mark"), user }
    }

    /// The core's keys for the same user key.
    fn core(k: &Keys) -> CoreKeys {
        use dybw_core::crypto::{MarkScheme, Marker};
        let user = CoreKey::from_bytes(&k.user.to_bytes()).unwrap();
        CoreKeys { marker: Marker::new(&user, MarkScheme::Bwss), user, orgs: BTreeMap::new(), security_version: 0 }
    }

    /// `super::build` with a fresh scan cache, bound as `previous` was.
    fn build(sync: &Value, k: &Keys, previous: Option<&Built>) -> Built {
        let bound = previous.map(|p| p.bound.clone()).unwrap_or_default();
        super::build(sync, &core(k), previous, &mut UnmarkedCache::default(), &bound, false)
    }

    fn build_list(view: &[Cow<'_, Value>], k: &Keys, previous: Option<&Built>) -> Built {
        build(&json!({ "ciphers": view }), k, previous)
    }

    fn build_fresh(sync: &Value, queue: &Queue, k: &Keys, folder: Option<&str>) -> Built {
        super::build_fresh(sync, queue, &core(k), folder, &mut UnmarkedCache::default(), &Bindings::new(), false)
    }

    fn with_queue<'a>(sync: &'a Value, ops: Vec<Op>, k: &Keys) -> Vec<Cow<'a, Value>> {
        let built = build(sync, k, None);
        super::with_queue(sync, &Queue { ops, registry: vec![] }, &core(k), None, &built)
    }

    fn delete(id: &str, cid: &str) -> Op {
        Op::Delete { id: id.into(), base_revision: REV.into(), cipher_id: Some(cid.into()), organization_id: None }
    }

    /// A key of the core's, for the queue file.
    fn ck() -> CoreKey {
        CoreKey::generate(&OsRandom).unwrap()
    }

    fn read_registry(cipher: &Value, k: &Keys) -> Result<Option<Registry>, RegistryError> {
        super::read_registry(cipher, &core(k))
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
        let (k, mut cache) = (keys(), UnmarkedCache::default());
        let none = Bindings::new();
        let first =
            super::build(&sync(vec![login(&k, "c9", &[("other", "x")])]), &core(&k), None, &mut cache, &none, false);
        assert!(!first.snapshot.held.contains("c9"));
        let mut garbled = login(&k, "c9", &[]);
        garbled["fields"] = json!([{ "type": 0, "name": "2.bad|bad|bad", "value": "2.bad|bad|bad" }]);
        let s = sync(vec![garbled]);
        // The core's cache lives with the keyring: the same cipher is not opened again.
        let again = super::build(&s, &core(&k), Some(&first), &mut cache, &none, false);
        assert!(!again.snapshot.held.contains("c9"), "still known as unmarked");
        // Rescanned, the same cipher cannot be read.
        assert!(build(&s, &k, None).snapshot.held.contains("c9"));
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
        let view = with_queue(&s, vec![delete("b", "c2")], &k);
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
        let queue = Queue { ops: vec![Op::Create(new_item_of(&new, None)), delete("b", "c2")], registry: vec![] };
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
        assert_eq!(keyring_folder(&s, &core(&k).user, "secret-service").as_deref(), Some("f1"));
        assert_eq!(keyring_folder(&s, &core(&k).user, "nope"), None);
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

    const UK: &str = "uk-1";

    fn one_op() -> Queue {
        Queue { ops: vec![delete("a", "c1")], registry: vec![] }
    }

    /// `one_op` as bwss's format-2/3 writer sealed it: the JSON list inside.
    const ONE_OP_V3: &[u8] = br#"[{"Delete":{"id":"a","base_revision":"2026-01-02T03:04:05Z","cipher_id":"c1"}}]"#;

    fn seal(queue: &Queue, key: &CoreKey) -> Value {
        super::seal(queue, &Records::new(), key, UK, &OsRandom).unwrap()
    }

    fn read_file(path: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    /// `one_op` as an older bwss wrote it, as format 2 or 3 under `key`.
    fn legacy_file(format: u64, key: &CoreKey) -> Vec<u8> {
        serde_json::to_vec(&json!({ "format": format, "ops": key.encrypt(ONE_OP_V3, &OsRandom).unwrap() })).unwrap()
    }

    /// A queue as bwss wrote it before the queue key: format 2, sealed with
    /// the user key itself. A same-user process can forge exactly this.
    fn legacy_queue(user: &CoreKey) -> Vec<u8> {
        legacy_file(2, user)
    }

    struct QueueDir {
        _dir: tempfile::TempDir,
        path: PathBuf,
        records: PathBuf,
        flag: PathBuf,
        aside: PathBuf,
    }

    fn queue_dir() -> QueueDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/queue.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let records = dir.path().join("state/write-records");
        let flag = dir.path().join("tool-state/queue-key-migrated");
        let aside = dir.path().join("state/queue.json.unsealable");
        QueueDir { _dir: dir, path, records, flag, aside }
    }

    fn load_file(q: &QueueDir, user: &CoreKey) -> Result<QueueFile, BackendError> {
        load_queue(&q.path, &q.records, user, UK, &q.flag)
    }

    fn load(q: &QueueDir, user: &CoreKey) -> Result<Queue, BackendError> {
        load_file(q, user).map(|f| f.queue)
    }

    #[test]
    fn the_queue_is_sealed_with_a_key_of_its_own_as_format_4() {
        let q = queue_dir();
        let user = ck();
        let file = seal(&one_op(), &queue_key(&user));
        assert_eq!(file["format"], 4);
        std::fs::write(&q.path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert_eq!(load(&q, &user).unwrap().len(), 1);
        assert!(q.path.exists());
        assert!(!v3_backup(&q.path).exists(), "nothing to keep");
        assert!(crate::config::flag_set(&q.flag), "a queue under the queue key means the move is done");
    }

    #[test]
    fn a_pre_migration_queue_is_resealed_once_and_the_flag_set() {
        let q = queue_dir();
        let user = ck();
        std::fs::write(&q.path, legacy_queue(&user)).unwrap();
        assert_eq!(load(&q, &user).unwrap().len(), 1);
        let resealed = read_file(&q.path);
        assert_eq!(resealed["format"], 4);
        assert_eq!(unseal(&resealed, &queue_key(&user), UK).unwrap().0.len(), 1);
        assert!(crate::config::flag_set(&q.flag));
        assert_eq!(load(&q, &user).unwrap().len(), 1);
        assert!(!q.aside.exists());
    }

    #[test]
    fn format2_still_opens_once_under_the_flag() {
        let q = queue_dir();
        let user = ck();
        let old = legacy_queue(&user);
        std::fs::write(&q.path, &old).unwrap();
        // Opened with the user key while the flag is absent, and migrated.
        let back = load(&q, &user).unwrap();
        assert!(matches!(&back.ops[..], [Op::Delete { id, cipher_id: Some(c), organization_id: None, .. }]
            if id == "a" && c == "c1"));
        assert_eq!(read_file(&q.path)["format"], 4);
        assert_eq!(std::fs::read(v3_backup(&q.path)).unwrap(), old, "kept as it was");
        assert!(crate::config::flag_set(&q.flag));
        // Never again: the same file planted afterwards is set aside unopened.
        std::fs::write(&q.path, &old).unwrap();
        assert!(load(&q, &user).unwrap().is_empty());
        assert_eq!(std::fs::read(&q.aside).unwrap(), old);
    }

    #[test]
    fn format3_queue_migrates_every_op_in_order() {
        use dybw_core::vault::write::{HistoryAnswer, HistoryQuestion};
        // Written by bwss's format-3 writer (e37e0c3), sealed with this key.
        let recorded: Value = serde_json::from_str(include_str!("../../tests/fixtures/queue-v3.json")).unwrap();
        let plain = CoreKey::from_bytes(&[7; 64]).unwrap().decrypt(recorded["ops"].as_str().unwrap()).unwrap();
        let q = queue_dir();
        let user = ck();
        let old = json!({ "format": 3, "ops": queue_key(&user).encrypt(&plain, &OsRandom).unwrap() });
        std::fs::write(&q.path, serde_json::to_vec(&old).unwrap()).unwrap();
        std::fs::write(
            &q.records,
            queue_key(&user).encrypt(br#"{"id-p":{"written":[],"confirmed":true}}"#, &OsRandom).unwrap(),
        )
        .unwrap();

        let file = load_file(&q, &user).unwrap();
        let ops = &file.queue.ops;
        assert_eq!(ops.iter().map(target).collect::<Vec<_>>(), ["id-new", "id-p", "id-d"], "in order");
        let Op::Create(new) = &ops[0] else { panic!("expected a create") };
        assert_eq!(
            (new.id.as_str(), new.name.as_str(), new.value.as_slice()),
            ("id-new", "Router admin", &b"new-secret"[..])
        );
        assert_eq!(new.folder_id, None, "found or made when sent");
        let fields: Vec<(&str, &str, bool)> =
            new.tool_fields.iter().map(|f| (f.name.as_str(), f.value.as_str(), f.hidden)).collect();
        assert_eq!(
            fields,
            [
                ("bwss:attr:service", "router", false),
                ("bwss:attr:user", "admin", false),
                ("bwss:collection", "work", false),
                ("bwss:label", "Router admin", false),
                ("bwss:content-type", "application/octet-stream", false),
                ("bwss:acl", "/usr/bin/a", true),
                ("bwss:created", "1700000000", false),
            ]
        );
        let Op::Patch(p) = &ops[1] else { panic!("expected a patch") };
        assert_eq!(
            (p.cipher_id.as_deref(), p.base_revision.as_str(), p.organization_id.as_deref()),
            (Some("c2"), "r2", None)
        );
        assert_eq!(
            p.set.iter().map(|f| (f.name.as_str(), f.value.as_str(), f.hidden)).collect::<Vec<_>>(),
            [("bwss:label", "New label", false)]
        );
        assert_eq!(p.remove, ["bwss:attr:"]);
        let [acl] = p.append_lines.as_slice() else { panic!("one line append") };
        assert_eq!(
            (acl.name.as_str(), acl.lines.len(), acl.lines[0].as_str(), acl.hidden),
            ("bwss:acl", 1, "/usr/bin/b", true)
        );
        assert!(matches!(&p.value, ValueChange::Set { source: CoreSource::Notes, secret, base_mark, owned: true }
            if secret.as_slice() == b"pw" && *base_mark == [9; 32]));
        assert_eq!(p.answer, Some((HistoryQuestion::FirstWriteBack, HistoryAnswer::WriteToLogin)));
        assert!(matches!(&ops[2], Op::Delete { base_revision, cipher_id: Some(c), organization_id: None, .. }
            if base_revision == "r3" && c == "c3"));
        let [reg] = file.queue.registry.as_slice() else { panic!("one registry op") };
        assert_eq!((reg.collection.as_str(), reg.entry.label.as_str(), reg.entry.created), ("work", "Work", 5));
        assert!(file.records["id-p"].confirmed, "the records beside it are carried over");

        // One format-4 file holds it all now; the old one is kept until a flush moves on.
        let now = read_file(&q.path);
        assert_eq!((&now["format"], &now["user_key_id"], &now["count"]), (&json!(4), &json!(UK), &json!(4)));
        assert_eq!(read_file(&v3_backup(&q.path)), old);
        assert!(!q.records.exists());
        assert!(crate::config::flag_set(&q.flag));
        let again = load_file(&q, &user).unwrap();
        assert_eq!(
            (again.queue.ops.iter().map(target).collect::<Vec<_>>(), again.queue.registry.len()),
            (vec!["id-new", "id-p", "id-d"], 1)
        );
        assert!(again.records["id-p"].confirmed);
    }

    #[test]
    fn queue_from_another_user_key_is_set_aside() {
        let q = queue_dir();
        let user = ck();
        let three = Queue { ops: vec![delete("a", "c1"), delete("b", "c2")], registry: one_reg() };
        // Sealed for a user key this unlock does not hold: never opened.
        let file = super::seal(&three, &Records::new(), &queue_key(&ck()), "uk-old", &OsRandom).unwrap();
        let bytes = serde_json::to_vec(&file).unwrap();
        std::fs::write(&q.path, &bytes).unwrap();
        let loaded = load_file(&q, &user).unwrap();
        assert!(loaded.queue.is_empty());
        let aside = q.path.with_file_name("queue.uk-old.bak");
        assert_eq!(std::fs::read(&aside).unwrap(), bytes, "set aside as it was");
        assert!(!q.path.exists());
        assert_eq!(loaded.notices.len(), 1);
        let notice = &loaded.notices[0];
        assert!(notice.contains("3 changes") && notice.contains(&aside.display().to_string()), "{notice}");
        // A second one goes beside it; an id never names a path elsewhere.
        let mut evil = file;
        evil["user_key_id"] = json!("../uk-old");
        evil["count"] = json!(1);
        std::fs::write(&q.path, serde_json::to_vec(&evil).unwrap()).unwrap();
        let notice = load_file(&q, &user).unwrap().notices.concat();
        assert!(notice.contains("1 change ") && notice.contains("queue.uk-old.bak.2"), "{notice}");
    }

    fn one_reg() -> Vec<super::super::ops::RegistryOp> {
        let entry = super::super::registry::Entry { label: "Work".into(), created: 5, deleted: false };
        vec![super::super::ops::RegistryOp { collection: "work".into(), entry }]
    }

    #[test]
    fn a_damaged_queue_is_set_aside_as_today() {
        let user = ck();
        let mut tampered = seal(&one_op(), &queue_key(&user));
        let enc = tampered["set"].as_str().unwrap().replacen("2.", "2.A", 1);
        tampered["set"] = json!(enc);
        for (bytes, suffix) in [
            (b"{\"format\":4,".to_vec(), "corrupt"),
            (b"{\"format\":1,\"ops\":[]}".to_vec(), "legacy"),
            (serde_json::to_vec(&tampered).unwrap(), "unsealable"),
        ] {
            let q = queue_dir();
            std::fs::write(&q.path, &bytes).unwrap();
            assert!(load(&q, &user).unwrap().is_empty(), "nothing is replayed");
            assert!(!q.path.exists());
            assert_eq!(std::fs::read(q.path.with_file_name(format!("queue.json.{suffix}"))).unwrap(), bytes);
            assert!(!v3_backup(&q.path).exists());
        }
    }

    #[test]
    fn write_records_kept_beside_the_queue_move_into_it() {
        let q = queue_dir();
        let user = ck();
        std::fs::write(
            &q.records,
            queue_key(&user).encrypt(br#"{"gh":{"written":[],"confirmed":true}}"#, &OsRandom).unwrap(),
        )
        .unwrap();
        // No queue at all: the records still move into a queue file.
        let file = load_file(&q, &user).unwrap();
        assert!(file.queue.is_empty() && file.records["gh"].confirmed);
        assert!(!q.records.exists());
        assert_eq!(unseal(&read_file(&q.path), &queue_key(&user), UK).unwrap().1, file.records);
        // A records file that does not open is no records; a format-4 queue's own records win.
        std::fs::write(&q.records, "2.garbage").unwrap();
        assert!(load_file(&q, &user).unwrap().records["gh"].confirmed);
        assert!(!q.records.exists());
        std::fs::remove_file(&q.path).unwrap();
        std::fs::write(&q.records, "2.garbage").unwrap();
        assert!(load_file(&q, &user).unwrap().records.is_empty());
        // One that cannot be read or removed is left where it is.
        std::fs::remove_file(&q.path).unwrap();
        std::fs::create_dir_all(q.records.join("x")).unwrap();
        assert!(load_file(&q, &user).unwrap().records.is_empty());
        assert!(q.records.is_dir() && q.path.exists());
    }

    #[test]
    fn a_forged_user_key_queue_after_the_migration_is_never_replayed() {
        let user = ck();
        // Format 2 under the user key, and the same ciphertext labelled
        // format 3; format 4 sealed with the user key itself.
        let forged_v4 = serde_json::to_vec(&seal(&one_op(), &user)).unwrap();
        for forged in [legacy_queue(&user), legacy_file(3, &user), forged_v4] {
            let q = queue_dir();
            crate::config::set_flag(&q.flag, true, b"done\n").unwrap();
            std::fs::write(&q.path, &forged).unwrap();
            assert!(load(&q, &user).unwrap().is_empty(), "nothing is replayed");
            assert!(!q.path.exists());
            assert_eq!(std::fs::read(&q.aside).unwrap(), forged, "set aside as it was");
        }
    }

    #[test]
    fn no_queue_at_all_ends_the_migration_window() {
        let q = queue_dir();
        let user = ck();
        assert!(load(&q, &user).unwrap().is_empty());
        assert!(crate::config::flag_set(&q.flag));
        // A user-key queue planted afterwards is not opened with the user key.
        std::fs::write(&q.path, legacy_queue(&user)).unwrap();
        assert!(load(&q, &user).unwrap().is_empty());
        assert!(q.aside.exists());
    }

    #[test]
    fn a_queue_that_cannot_be_resealed_is_still_read_and_left_as_it_was() {
        let q = queue_dir();
        let user = ck();
        let old = legacy_queue(&user);
        std::fs::write(&q.path, &old).unwrap();
        // The private write goes through this temporary name: a directory
        // there makes it fail, even for root.
        std::fs::create_dir(crate::fsutil::temp_path(&q.path)).unwrap();
        assert_eq!(load(&q, &user).unwrap().len(), 1);
        assert_eq!(std::fs::read(&q.path).unwrap(), old);
        assert!(!crate::config::flag_set(&q.flag), "not moved yet: the window stays for the next try");
        // Nor when the old file cannot be kept first.
        std::fs::remove_dir(crate::fsutil::temp_path(&q.path)).unwrap();
        std::fs::remove_file(v3_backup(&q.path)).unwrap();
        std::fs::create_dir(crate::fsutil::temp_path(&v3_backup(&q.path))).unwrap();
        assert_eq!(load(&q, &user).unwrap().len(), 1);
        assert_eq!(std::fs::read(&q.path).unwrap(), old);
        assert!(!crate::config::flag_set(&q.flag));
    }

    #[test]
    fn a_queue_that_opens_with_neither_key_is_kept_aside() {
        let q = queue_dir();
        let foreign = serde_json::to_vec(&seal(&one_op(), &ck())).unwrap();
        std::fs::write(&q.path, &foreign).unwrap();
        assert!(load(&q, &ck()).unwrap().is_empty());
        assert!(!q.path.exists());
        assert_eq!(std::fs::read(&q.aside).unwrap(), foreign, "set aside as it was, never lost");
    }

    #[test]
    fn skipped_and_uninspectable_items_say_why() {
        use dybw_core::vault::SkipReason as S;
        use dybw_core::vault::Uninspectable as U;
        let features = ["bwss:future".to_owned(), "dybw:x".to_owned()];
        for (reason, text) in [
            (S::WrongType, "its item type is not supported"),
            (S::EncodingOnUserSource, "bwss:encoding=base64 on a value bwss does not own"),
            (S::UnknownLocation, "unknown bwss:location"),
            (S::UnknownEncoding, "unknown bwss:encoding"),
            (S::InvalidId, "its bwss:id is not valid"),
            (S::ReservedId, "_collections is reserved for the collection registry"),
            (S::ViewPasswordHidden, "its password is hidden from this account"),
            (S::InvalidBase64, "value is not valid base64"),
            (
                S::NewerFormat,
                "it needs what this bwss does not implement (bwss:future, dybw:x): it is not used until bwss is updated",
            ),
        ] {
            assert_eq!(skip_text(reason, &features), text);
        }
        let all = [
            U::OrganizationNotRead,
            U::OrganizationKeyMissing,
            U::ItemKey,
            U::FieldNames,
            U::Marker,
            U::Value,
            U::NewerFormat,
            U::Blob,
            U::TooLarge,
        ];
        let texts: HashSet<&str> = all.into_iter().map(uninspectable_text).collect();
        assert_eq!(texts.len(), all.len(), "one text each");
    }

    #[test]
    fn a_value_in_the_notes_and_a_session_collection_are_read_as_before() {
        let k = keys();
        let c = note(&k, "c1", &[("bwss:id", "n"), ("bwss:location", "notes"), ("bwss:collection", " Session ")], "v");
        let b = build(&sync(vec![c]), &k, None);
        assert_eq!(b.marked["n"].source, ValueSource::BwssNotes);
        assert_eq!(&*b.marked["n"].item.secret, b"v");
        assert_eq!(b.marked["n"].item.collection, LOGIN_COLLECTION, "session is memory only");
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
            cipher_id: None,
            organization_id: None,
            base_revision: REV.into(),
            set: vec![FieldSet { name: "bwss:label".into(), value: Zeroizing::new(label.into()), hidden: false }],
            remove: vec![],
            append_lines: vec![],
            value: ValueChange::Keep,
            answer: None,
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
            Op::Create(new_item_of(&d, None)),
            label_patch("a", "a2"),
            delete("b", "c2"),
            label_patch("c", "c1"),
            // A patch to an item whose create is queued goes to that create.
            label_patch("d", "d2"),
        ];
        let view = with_queue(&s, queue, &k);
        let ids: Vec<_> = view.iter().map(|c| c["id"].as_str().unwrap().to_owned()).collect();
        assert_eq!(ids, ["c1", "c3", ""], "b is gone, d is queued, nothing else moved");
        assert_eq!(
            view_labels(&view, &k),
            [("a".into(), "a2".into()), ("c".into(), "c1".into()), ("d".into(), "d2".into())]
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
        let view = with_queue(&s, vec![Op::Create(new_item_of(&big, None))], &k);
        assert_eq!(view.len(), 1);
        // ADR 0015: without bwss:label the label is the id, not the item name.
        assert_eq!(view_labels(&view, &k), [("a".to_owned(), "a".to_owned())]);
    }

    #[test]
    fn api_errors_are_retried_or_refused_by_their_status() {
        let http = |status| CoreApiError::Http { status, message: String::new() };
        for e in [http(429), http(500), http(503), CoreApiError::Network("reset".into()), CoreApiError::NotSynced] {
            let text = e.to_string();
            assert!(matches!(map_core_api(e), BackendError::Unavailable(m) if m == text), "{text}");
        }
        for e in [http(400), http(401), http(404), CoreApiError::Protocol("odd".into())] {
            let text = e.to_string();
            assert!(matches!(map_core_api(e), BackendError::Rejected(m) if m == text), "{text}");
        }
    }

    #[test]
    fn unlock_refusals_name_what_answers_them() {
        use dybw_core::api::ApiError as Core;
        use dybw_core::crypto::CryptoError;
        use dybw_core::ports::PortError;
        use dybw_core::profile::KdfSource;
        let weak = KdfParams::Pbkdf2 { iterations: 5_000 };
        let pinned = KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 };
        let text = |e: ProfileError| map_profile(e).to_string();
        assert!(matches!(map_profile(ProfileError::WrongPassword), BackendError::WrongPassword));
        assert!(matches!(map_profile(Core::Network("x".into()).into()), BackendError::Unavailable(_)));
        assert!(matches!(map_profile(Core::WrongOrigin.into()), BackendError::Rejected(_)));
        assert!(
            matches!(map_profile(PortError("disk".into()).into()), BackendError::Unavailable(m) if m == "host port failed: disk")
        );
        assert!(matches!(map_profile(CryptoError::BadMac.into()), BackendError::Rejected(_)));
        assert!(
            matches!(map_profile(ProfileError::IncompleteUnlockData), BackendError::Rejected(m) if m.contains("no usable unlock data") && m.contains("unlock online"))
        );
        let weakened = text(ProfileError::KdfWeakened { pinned, offered: weak, kdf_source: KdfSource::SyncUnlockData });
        assert_eq!(
            weakened,
            "the KDF from sync unlock data (PBKDF2, 5000 iterations) is weaker than the one pinned on this device \
             (Argon2id, 3 iterations, 64 MiB, parallelism 4): check it in the web vault, then run `bwss kdf accept`"
        );
        assert!(text(ProfileError::KdfPinUnreadable).ends_with("then run `bwss kdf accept`"));
        assert!(
            text(ProfileError::SecurityDowngrade { seen: 3, offered: 2 }).ends_with("run `bwss security accept 2`")
        );
        let stored = text(ProfileError::SecurityState(SecurityFault::StoredUnreadable));
        assert!(stored.contains("`bwss security accept 0` forgets it"), "{stored}");
        for (fault, says) in [(SecurityFault::Missing, "is missing"), (SecurityFault::Invalid, "is invalid")] {
            let shown = text(ProfileError::SecurityState(fault));
            assert!(matches!(map_profile(ProfileError::SecurityState(fault)), BackendError::SecurityState(_)));
            assert!(shown.contains(says) && shown.ends_with("check the account in the web vault"), "{shown}");
        }
    }

    #[test]
    fn the_cache_keeps_the_kdf_as_bwss_always_wrote_it() {
        let argon = KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 };
        let stored = serde_json::to_value(StoredKdf::from(argon)).unwrap();
        assert_eq!(stored, json!({ "type": "argon2id", "iterations": 3, "memory_mib": 64, "parallelism": 4 }));
        assert_eq!(KdfParams::from(serde_json::from_value::<StoredKdf>(stored).unwrap()), argon);
        let pbkdf2 = json!({ "type": "pbkdf2", "iterations": 600_000 });
        let read = KdfParams::from(serde_json::from_value::<StoredKdf>(pbkdf2).unwrap());
        assert_eq!(read, KdfParams::Pbkdf2 { iterations: 600_000 });
    }

    #[tokio::test]
    async fn the_kdf_an_unlock_ran_is_read_from_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().as_os_str().to_owned();
        let storage = FileStorage::new(&Paths::with(|v| (v == "HOME").then(|| home.clone())), "p");
        assert_eq!(ran_kdf(&storage).await, None);
        let argon = KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 };
        dybw_core::profile::accept_kdf(&storage, argon, "o").await.unwrap();
        assert_eq!(ran_kdf(&storage).await, Some(argon));
        storage.save("kdf-pin", br#"{"kdf":7,"iterations":1,"memory":0,"parallelism":0,"origin":"o"}"#).await.unwrap();
        assert_eq!(ran_kdf(&storage).await, None);
    }

    #[test]
    fn a_migration_flag_that_cannot_be_set_does_not_stop_the_queue() {
        let q = queue_dir();
        // A file where the flag's directory should be: setting it fails.
        let blocker = q.flag.parent().unwrap();
        std::fs::write(blocker, b"x").unwrap();
        let user = ck();
        assert!(load(&q, &user).unwrap().is_empty());
        assert!(!crate::config::flag_set(&q.flag), "not recorded, so the window stays open");
        assert_eq!(std::fs::read(blocker).unwrap(), b"x");
    }

    #[test]
    fn a_queue_that_cannot_be_read_is_never_touched() {
        let q = queue_dir();
        let user = ck();
        // A directory where the file should be: reading it fails.
        std::fs::create_dir(&q.path).unwrap();
        let e = load(&q, &user).err().unwrap();
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
        let user = ck();
        let old = br#"{"format":1,"ops":[]}"#;
        std::fs::write(&q.path, old).unwrap();
        assert!(load(&q, &user).unwrap().is_empty());
        assert!(!q.path.exists());
        assert_eq!(std::fs::read(q.path.with_file_name("queue.json.legacy")).unwrap(), old);
    }

    #[test]
    fn an_old_queue_that_does_not_open_with_the_user_key_is_kept_aside() {
        let q = queue_dir();
        let mut file = seal(&one_op(), &ck());
        file["format"] = json!(2);
        let foreign = serde_json::to_vec(&file).unwrap();
        std::fs::write(&q.path, &foreign).unwrap();
        assert!(load(&q, &ck()).unwrap().is_empty());
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
        let foreign = serde_json::to_vec(&seal(&one_op(), &ck())).unwrap();
        std::fs::write(&long, &foreign).unwrap();
        let e = load_queue(&long, &q.records, &ck(), UK, &q.flag).err().unwrap();
        assert!(matches!(&e, BackendError::Unavailable(m) if m.contains("left untouched")), "{e}");
        assert_eq!(std::fs::read(&long).unwrap(), foreign);
    }
}
