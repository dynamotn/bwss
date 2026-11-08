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
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use dybw_core::api::{ApiKey as CoreApiKey, Client, DeviceInfo, ServerUrls};
use dybw_core::crypto::{AwsLcRsa, KdfParams, SymmetricKey as CoreKey};
use dybw_core::ports::Storage;
use dybw_core::profile::{self, CachedSync, ProfileError, SecurityFault, UnlockWarning};
use dybw_core::sync::is_rollback;
use dybw_core::vault::fields as core_fields;
use dybw_core::vault::{
    Keys as CoreKeys, MarkedItem as CoreItem, Namespace, Organizations, SkipReason, Uninspectable, UnmarkedCache,
    ValueSource as CoreSource, item_meta, scan_vault_with,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::ops::{
    FORMAT as LEGACY_QUEUE_FORMAT, Loaded, Op, QUEUE_FORMAT, read_formats, read_versioned, seal, set_aside, unseal,
};
use super::registry::{REGISTRY_ID, Registry};
use super::runner::{Effect, status_lines};
use super::worker::{Command, Worker, WorkerHandle};
use super::{AclTrust, Backend, BackendError, kdf_text};
use crate::bw::api::{Api, ApiError, ApiKey, resolve_server_urls};
use crate::bw::crypto::SymmetricKey;
use crate::bw::fields::{
    A_ID, A_NAME, A_URI, A_USERNAME, DERIVED, F_ACL, F_COLLECTION, F_CONTENT_TYPE, F_CREATED, F_ENCODING, F_ID, F_KIND,
    F_LABEL, F_LOCATION,
};
use crate::bw::items::parse_date;
use crate::bw::scan::{Keys, MarkedItem, Scan, ValueSource, normalize_collection, resolve_duplicates, scan};
use crate::bw::write::{apply, new_note};
use crate::config::{Config, Credentials, Paths};
use crate::core_ports::{
    clock::SystemClock, http::HttpPort, kdf::BlockingArgon2, random::OsRandom, storage::FileStorage,
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
/// Why a COSE account takes no writes yet.
const COSE_READ_ONLY: &str =
    "this account's user key is a COSE key: this bwss reads its items but cannot write to it yet, and writes nothing";

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

/// Bridge until B5-B6: bwss's own code writes with its own key type, which
/// holds a legacy key only. A COSE key gets a random stand-in that opens
/// nothing, and the keyring takes no writes (`true`); reads use the core's keys.
fn bridge_keys(user: &dybw_core::crypto::SymmetricKey) -> Result<(Keys, bool), BackendError> {
    let (user, read_only) = match SymmetricKey::from_bytes(&user.to_bytes()) {
        Ok(user) => (user, false),
        Err(_) => {
            let mut bytes = Zeroizing::new([0u8; 64]);
            rand::fill(bytes.as_mut_slice());
            (SymmetricKey::from_bytes(bytes.as_ref()).map_err(|e| BackendError::Rejected(e.to_string()))?, true)
        }
    };
    Ok((Keys { mark: user.derive("value-mark"), user }, read_only))
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
    /// Scan cache of the write path: `(cipher id, raw revisionDate)` of
    /// unmarked ciphers.
    pub unmarked: HashSet<(String, String)>,
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

/// Scan-cache key of a cipher; `None` when it has no revision to compare.
pub(super) fn cache_key(cipher: &Value) -> Option<(String, String)> {
    let id = cipher.get("id").and_then(Value::as_str).filter(|id| !id.is_empty())?;
    let rev = cipher.get("revisionDate").filter(|r| !r.is_null())?;
    Some((id.to_owned(), rev.to_string()))
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

fn uninspectable_text(why: Uninspectable) -> &'static str {
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
/// else the id (ADR 0015); a name, username or URI that does not decrypt is
/// left out of the derived attributes.
fn to_marked(m: CoreItem, keys: &CoreKeys) -> MarkedItem {
    let meta = item_meta(&m, keys);
    let tool = |name: &str| m.tool_fields.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str());
    let mut attributes: Attributes = m
        .attributes
        .iter()
        .filter(|(k, _)| !DERIVED.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    attributes.insert(A_ID.to_owned(), m.id.clone());
    for (k, v) in [(A_NAME, &meta.name), (A_USERNAME, &meta.username), (A_URI, &meta.uri)] {
        if let Some(v) = v.as_deref().filter(|v| !v.is_empty()) {
            attributes.insert(k.to_owned(), v.clone());
        }
    }
    let label = tool(F_LABEL).filter(|l| !l.is_empty()).unwrap_or(&m.id).to_owned();
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
        report.items.into_iter().map(|m| (m.id.clone(), to_marked(m, keys))).collect();
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
    let unmarked = list.iter().filter(|c| !report.present.contains(cipher_id(c))).filter_map(cache_key).collect();

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
        unmarked,
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
/// A winner that is a queued create has no server cipher and is left out,
/// and so is every cipher `built` did not serve: a duplicate it left out,
/// a held one, one that needs a newer format (ADR 0019, ADR 0020).
fn marked_positions<C: Borrow<Value>>(list: &[C], keys: &Keys, built: &Built) -> HashMap<String, usize> {
    let mut found = Vec::new();
    for c in list.iter().map(Borrow::borrow) {
        if cache_key(c).is_some_and(|k| built.unmarked.contains(&k)) || built.snapshot.held.contains(cipher_id(c)) {
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
pub(super) fn find_marked<C: Borrow<Value>>(list: &[C], id: &str, keys: &Keys, built: &Built) -> Option<usize> {
    marked_positions(list, keys, built).get(id).copied()
}

/// The ciphers with every queued op applied, so pending writes stay visible
/// (design §8.2 step 3). Only the ciphers the ops touch are copied; the rest
/// stay borrowed from `sync`.
pub(super) fn with_queue<'a>(
    sync: &'a Value,
    queue: &[Op],
    keys: &Keys,
    folder: Option<&str>,
    built: &Built,
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
                let map = positions.get_or_insert_with(|| marked_positions(&list, keys, built));
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
                let map = positions.get_or_insert_with(|| marked_positions(&list, keys, built));
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

/// The keys a build needs: bwss's own for the queued ops (until B5), the
/// core's for the scan.
pub(super) struct BuildKeys<'a> {
    pub legacy: &'a Keys,
    pub core: &'a CoreKeys,
}

/// Builds the keyring from the cache with the queue applied, on top of
/// `previous`.
fn build_view(
    sync: &Value,
    queue: &[Op],
    keys: BuildKeys<'_>,
    folder: Option<&str>,
    previous: &Built,
    cache: &mut UnmarkedCache,
) -> Built {
    let mut built = if queue.is_empty() {
        build(sync, keys.core, Some(previous), cache, &previous.bound)
    } else {
        let view: Vec<Value> =
            with_queue(sync, queue, keys.legacy, folder, previous).into_iter().map(Cow::into_owned).collect();
        build(&json!({ "ciphers": view }), keys.core, Some(previous), cache, &previous.bound)
    };
    if queue.iter().any(|op| matches!(op, Op::Registry { .. })) {
        // `built.registry` stays the server's: only what is shown changes.
        let shown = registry_with_queue(&built.registry, queue);
        built.snapshot.collections = collection_list(&shown, &built.snapshot.items);
    }
    built
}

/// Builds the keyring for a freshly loaded cache and queue.
fn build_fresh(
    sync: &Value,
    queue: &[Op],
    keys: BuildKeys<'_>,
    folder: Option<&str>,
    cache: &mut UnmarkedCache,
    bound: &Bindings,
) -> Built {
    let base = build(sync, keys.core, None, cache, bound);
    if queue.is_empty() {
        return base;
    }
    build_view(sync, queue, keys, folder, &base, cache)
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
    /// Bridge until B5-B6: bwss's own key type, from `core_keys`, for writes.
    pub(super) keys: Keys,
    /// The keys dybw-core opened.
    pub(super) core_keys: CoreKeys,
    kdf: Option<KdfParams>,
    /// The server's copy of the vault, as cached; queued ops are not in it.
    pub(super) sync: Value,
    /// Raw account revision date of `sync`, when known.
    revision: Option<String>,
    /// The keyring: `sync` with the queue applied.
    pub(super) built: Built,
    /// The core's scan cache: the unmarked ciphers of the last build.
    cache: UnmarkedCache,
    pub(super) keyring_folder: Option<String>,
    /// What `bwss status` reports about this unlock.
    notices: Vec<String>,
    /// Ids the server sent older than the cached copy, which is kept (ADR 0019).
    rollbacks: Vec<Rollback>,
    /// Bridge until B5-B6: a COSE user key, which bwss's own write code cannot use.
    read_only: bool,
}

pub(crate) struct Bitwarden {
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
    /// Bumped by every `lock`: an unlock that started before one never
    /// installs its keys.
    lock_generation: AtomicU64,
    /// Where dybw-core's client goes, and as which device.
    urls: ServerUrls,
    device: DeviceInfo,
    /// dybw-core's device state: the KDF pin, the security version, the user key id.
    storage: FileStorage,
    /// The sealed `BINDINGS` file, written from the worker without awaiting.
    bindings_path: PathBuf,
    /// An accept record a sync used but could not remove: never used again.
    spent_accept: std::sync::Mutex<Option<Vec<Rollback>>>,
    acl_confirmed: PathBuf,
}

/// The online half of an unlock.
#[expect(
    clippy::large_enum_variant,
    reason = "one per unlock; a Box would leave a copy of the keys unwiped on the heap"
)]
enum Online {
    Opened(profile::Unlocked, Option<String>),
    /// The network is down: the offline copy may be used.
    Unreachable(String),
}

fn unavailable(e: impl std::fmt::Display) -> BackendError {
    BackendError::Unavailable(e.to_string())
}

fn map_api(e: ApiError) -> BackendError {
    if e.is_transient() { BackendError::Unavailable(e.to_string()) } else { BackendError::Rejected(e.to_string()) }
}

fn map_core_api(e: dybw_core::api::ApiError) -> BackendError {
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
        let urls = resolve_server_urls(&config.server_url).map_err(anyhow::Error::msg)?;
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
            api: Mutex::new(Api::new(urls, device_id.clone())?),
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
            spent_accept: std::sync::Mutex::new(None),
            acl_confirmed: paths.acl_confirmed(),
        })
    }

    fn core_key(&self) -> CoreApiKey {
        CoreApiKey {
            origin: self.key.origin.clone(),
            client_id: self.key.client_id.clone(),
            client_secret: self.key.client_secret.clone(),
        }
    }

    /// `profile::unlock` with bwss's ports. A network that is down is not
    /// an error here: the caller falls back to the offline copy.
    async fn open_online(&self, password: Zeroizing<String>) -> Result<Online, BackendError> {
        // Bridge until B5: bwss's own client still writes, so it logs in and
        // reads the revision (before `/sync`, as it always did) here.
        let revision = match self.ensure_login().await {
            Ok(()) => self.api.lock().await.revision_date().await.ok(),
            Err(e) if e.is_transient() => return Ok(Online::Unreachable(e.to_string())),
            Err(e) => return Err(map_api(e)),
        };
        let http = HttpPort::new().map_err(unavailable)?;
        let mut client =
            Client::new(http, SystemClock, self.urls.clone(), self.device.clone()).map_err(map_core_api)?;
        let (ns, orgs) = (&Namespace::BWSS, &Organizations::None);
        let opened = profile::unlock(
            &mut client,
            &self.storage,
            &self.core_key(),
            &self.email,
            password,
            &BlockingArgon2,
            &AwsLcRsa,
            ns,
            orgs,
        )
        .await;
        match opened {
            Ok(unlocked) => {
                self.api.lock().await.synced(&unlocked.sync);
                Ok(Online::Opened(unlocked, revision))
            }
            Err(ProfileError::Api(e)) if e.is_transient() => Ok(Online::Unreachable(e.to_string())),
            Err(e) => Err(self.refused(e).await),
        }
    }

    /// Opens the user key online, else from the offline copy when the network
    /// is down: the unlocked profile, the account revision and whether it came
    /// from the copy.
    async fn open(&self, password: &str) -> Result<(profile::Unlocked, Option<String>, bool), BackendError> {
        let password = Zeroizing::new(password.to_owned());
        let why = match self.open_online(password.clone()).await? {
            Online::Opened(unlocked, revision) => return Ok((unlocked, revision, false)),
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
            Ok(unlocked) => Ok((unlocked, revision, true)),
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
            // Only the characters of an id the core makes: never a path.
            let name: String = old.chars().filter(|c| c.is_ascii_alphanumeric() || "-_".contains(*c)).collect();
            // Never over an earlier backup: the same old key can change away twice.
            let mut aside = self.queue_path.with_file_name(format!("queue.{name}.bak"));
            let mut n = 1;
            while std::fs::symlink_metadata(&aside).is_ok() {
                n += 1;
                aside = self.queue_path.with_file_name(format!("queue.{name}.bak.{n}"));
            }
            match std::fs::rename(&self.queue_path, &aside) {
                Ok(()) => notices.push(format!(
                    "the user key changed: changes queued before that cannot be sent and were set aside in {}",
                    aside.display()
                )),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    notices.push(format!("the user key changed, and the write queue could not be set aside: {e}"))
                }
            }
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

    /// Bridge until B4-B6: a COSE account takes no writes.
    async fn writable(&self) -> Result<(), BackendError> {
        match self.state.lock().await.as_ref() {
            Some(state) if state.read_only => Err(BackendError::Rejected(COSE_READ_ONLY.into())),
            _ => Ok(()),
        }
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
            kdf: state.kdf.map(StoredKdf::from),
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
    pub(super) fn rebuild(&self, state: &mut Unlocked, queue: &[Op]) {
        let keys = BuildKeys { legacy: &state.keys, core: &state.core_keys };
        let built =
            build_view(&state.sync, queue, keys, state.keyring_folder.as_deref(), &state.built, &mut state.cache);
        if built.bound != state.built.bound {
            self.save_bindings(&state.core_keys.user, &built.bound);
        }
        state.built = built;
    }

    /// The key the bindings are sealed with, as the queue is (design §8.1).
    fn bindings_key(user: &CoreKey) -> CoreKey {
        user.derive_bwss("queue")
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
    /// `Err` when it does not open.
    fn load_bindings(&self, user: &CoreKey) -> Result<Option<Bindings>, String> {
        match std::fs::read(&self.bindings_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
            Ok(raw) => String::from_utf8(raw)
                .map_err(|e| e.to_string())
                .and_then(|s| Self::bindings_key(user).decrypt(s.trim()).map_err(|e| e.to_string()))
                .and_then(|json| serde_json::from_slice(&json).map_err(|e| e.to_string()))
                .map(Some),
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
        self.rebuild(state, queue);
    }

    /// Keeps the queue on disk and shows it.
    pub(super) async fn queue_changed(&self, queue: &[Op]) -> Result<(), BackendError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        // Logged in `save_queue`; the change is already in memory.
        let _ = self.save_queue(queue, &state.keys.user);
        self.rebuild(state, queue);
        Ok(())
    }
}

/// The [`Backend`] operations, run by the worker: their futures await the
/// core's, which are not `Send`.
impl Bitwarden {
    pub(crate) async fn unlock(&self, password: &str) -> Result<Snapshot, BackendError> {
        let generation = self.lock_generation.load(Ordering::SeqCst);
        let (unlocked, revision, from_cache) = self.open(password).await?;
        let mut notices = self.check_user_key(&unlocked.user_key_id()).await;
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
        let (keys, read_only) = bridge_keys(&unlocked.keys.user)?;
        if read_only {
            tracing::warn!("{COSE_READ_ONLY}");
            notices.push(COSE_READ_ONLY.into());
        }
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
                build(copy, &core_keys, None, &mut UnmarkedCache::default(), &Bindings::new()).bound
            }
        };
        let rollbacks = base.map(|base| hold_rollbacks(&base.sync, &mut sync, &bound, &[]).0).unwrap_or_default();
        report_rollbacks(&rollbacks);
        self.keep_held_rollbacks(&rollbacks).await;

        let mut queue = self.queue.lock().await;
        // A COSE account's queue is left as it is, for B6 to open.
        *queue = if read_only { Vec::new() } else { load_queue(&self.queue_path, &keys.user, &self.queue_migrated)? };
        let folder = keyring_folder(&sync, &core_keys.user, &self.root);
        let mut cache = UnmarkedCache::default();
        let built = build_fresh(
            &sync,
            &queue,
            BuildKeys { legacy: &keys, core: &core_keys },
            folder.as_deref(),
            &mut cache,
            &bound,
        );
        if built.bound != bound {
            self.save_bindings(&core_keys.user, &built.bound);
        }
        let state = Unlocked {
            keys,
            core_keys,
            kdf,
            sync,
            revision,
            built,
            cache,
            keyring_folder: folder,
            notices,
            rollbacks,
            read_only,
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
        *self.state.lock().await = None;
        // A flush in progress clears the queue itself when it finds the
        // keyring locked; never wait for its network calls here.
        if let Ok(mut queue) = self.queue.try_lock() {
            queue.clear();
        }
        self.api.lock().await.logout();
        // Accepted for this session only.
        let _ = self.drop_accepted_rollbacks().await;
    }

    pub(crate) async fn refresh(&self) -> Result<Option<Snapshot>, BackendError> {
        let before = {
            let guard = self.state.lock().await;
            guard.as_ref().ok_or(BackendError::Locked)?.built.snapshot.clone()
        };
        // Before the first `/sync` of this session (offline unlock), writes
        // cannot name their owner: sync first, flush after.
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
            let revision = self.api.lock().await.revision_date().await.ok();
            let guard = self.state.lock().await;
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            if revision.is_some() && revision == state.revision {
                return Ok((state.built.snapshot != before).then(|| state.built.snapshot.clone()));
            }
        }
        let (revision, mut sync) = self.fetch().await.map_err(map_api)?;
        let held = {
            let queue = self.queue.lock().await;
            let mut guard = self.state.lock().await;
            let state = guard.as_mut().ok_or(BackendError::Locked)?;
            let (held, accepted) = hold_rollbacks(&state.sync, &mut sync, &state.built.bound, &accept);
            for r in &accepted {
                tracing::warn!(id = %r.id, cipher = %r.cipher, revision = %r.revision, "rollback accepted");
            }
            state.rollbacks = held;
            report_rollbacks(&state.rollbacks);
            state.keyring_folder = keyring_folder(&sync, &state.core_keys.user, &self.root);
            state.sync = sync;
            state.revision = revision;
            self.save_cache(state);
            self.rebuild(state, &queue);
            state.rollbacks.clone()
        };
        self.keep_held_rollbacks(&held).await;
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
        // Under the queue lock: no unlock can install a COSE key after the check.
        self.writable().await?;
        let result = self.create_collection_locked(&mut queue, label).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    pub(crate) async fn delete_collection(&self, id: &str, items: &[String]) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        // Under the queue lock: no unlock can install a COSE key after the check.
        self.writable().await?;
        let result = self.delete_collection_locked(&mut queue, id, items).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    pub(crate) async fn put_item(&self, item: &ItemData) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        // Under the queue lock: no unlock can install a COSE key after the check.
        self.writable().await?;
        let result = self.put_locked(&mut queue, item).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    pub(crate) async fn delete_item(&self, item: &ItemData) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        // Under the queue lock: no unlock can install a COSE key after the check.
        self.writable().await?;
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
        let queued = self.queue.lock().await.len();
        let urls = self.api.lock().await.urls().clone();
        let mut out = format!(
            "Bitwarden {} ({}), folder \"{}\", {queued} queued change(s)",
            self.email, urls.identity, self.root
        );
        if let Some(state) = self.state.lock().await.as_ref() {
            let rollbacks = (!state.rollbacks.is_empty()).then(|| rollback_text(&state.rollbacks));
            for line in status_lines(&state.built).into_iter().chain(rollbacks).chain(state.notices.iter().cloned()) {
                out.push('\n');
                out.push_str(&line);
            }
        }
        out
    }
}

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
pub struct BitwardenBackend(WorkerHandle);

impl BitwardenBackend {
    pub fn new(config: &Config, creds: Credentials, paths: &Paths) -> anyhow::Result<Self> {
        let (config, paths) = (config.clone(), paths.clone());
        Worker::spawn(move || Bitwarden::new(&config, creds, &paths)).map(Self)
    }

    #[cfg(test)]
    pub(super) async fn panic_for_test(&self) -> Result<(), BackendError> {
        self.0.call(Command::Panic).await
    }

    #[cfg(test)]
    pub(super) fn stopped_for_test() -> Self {
        Self(WorkerHandle::stopped())
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
        self.0.call(|r| Command::PutItem(item.clone(), r)).await?
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
    use crate::bw::write::{Patch, ValueChange};

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
        super::build(sync, &core(k), previous, &mut UnmarkedCache::default(), &bound)
    }

    fn build_list(view: &[Cow<'_, Value>], k: &Keys, previous: Option<&Built>) -> Built {
        build(&json!({ "ciphers": view }), k, previous)
    }

    fn build_fresh(sync: &Value, queue: &[Op], k: &Keys, folder: Option<&str>) -> Built {
        let keys = BuildKeys { legacy: k, core: &core(k) };
        super::build_fresh(sync, queue, keys, folder, &mut UnmarkedCache::default(), &Bindings::new())
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
        let (k, mut cache) = (keys(), UnmarkedCache::default());
        let none = Bindings::new();
        let first = super::build(&sync(vec![login(&k, "c9", &[("other", "x")])]), &core(&k), None, &mut cache, &none);
        let cached = ("c9".to_owned(), format!("\"{REV}\""));
        assert!(first.unmarked.contains(&cached));
        let mut garbled = login(&k, "c9", &[]);
        garbled["fields"] = json!([{ "type": 0, "name": "2.bad|bad|bad", "value": "2.bad|bad|bad" }]);
        let s = sync(vec![garbled]);
        // The core's cache lives with the keyring: the same cipher is not opened again.
        let again = super::build(&s, &core(&k), Some(&first), &mut cache, &none);
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
        let view = with_queue(&s, &queue, &k, None, &Built::default());
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
        let view = with_queue(&s, &queue, &k, None, &Built::default());
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
        let view = with_queue(&s, &queue, &k, None, &Built::default());
        assert_eq!(view.len(), 1);
        // ADR 0015: without bwss:label the label is the id, not the item name.
        assert_eq!(view_labels(&view, &k), [("a".to_owned(), "a".to_owned())]);
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
