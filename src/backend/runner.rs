//! The op runner: every write, live or queued, goes through dybw-core
//! (design §5, §8.3).
//!
//! A live op is sent with the core's writer (`sync::{update, create,
//! delete}`), which re-applies it to a fresh copy when the server says the
//! copy is out of date. Queued ops are kept and replayed with the core's
//! queue (`sync::queue::{enqueue, flush}`). What a failure means depends on
//! who waits for the op:
//!
//! * live (an app waits): a transient failure queues the op and the app gets
//!   `Ok`; anything else is an error to the app and nothing is queued;
//! * queued (a flush): a cause every op shares keeps the op and stops the
//!   flush; a cause of one item keeps that item's ops, and the others go on;
//!   a permanent failure drops the op with a warning, and the vault is read
//!   again.
//!
//! The collection registry and the keyring folder stay bwss's own writes.

use std::collections::{BTreeMap, HashSet};

use dybw_core::api::ApiError;
use dybw_core::crypto::SymmetricKey as CoreKey;
use dybw_core::sync::{self, DeleteOutcome, FlushReport, Op, SyncWriteError};
use dybw_core::vault::fields as core_fields;
use dybw_core::vault::write::{
    self as core_write, FieldSet, HistoryAnswer, HistoryQuestion, LineAppend, Patch, ValueChange, WriteError,
    WriteRecord, record_write,
};
use dybw_core::vault::{
    Keys as CoreKeys, Namespace, Organizations, Scan as CoreScan, ValueSource as CoreSource, scan as core_scan,
};
use serde_json::{Map, Value, json};
use tokio::sync::MutexGuard;
use zeroize::Zeroizing;

use super::bitwarden::{
    Bitwarden, Built, CoreClient, KIND_COLLECTIONS, QUEUED, Unlocked, ciphers, copy_keys, queue_key, read_registry,
    registry_with_queue, uninspectable_text, with_queue,
};
use super::ops::{Queue, Records, RegistryOp, new_item_of, target};
use super::registry::{Entry, REGISTRY_ID, Registry};
use super::{BackendError, question_text};
use crate::bw::fields::{F_ACL, F_ATTR, F_COLLECTION, F_CONTENT_TYPE, F_ID, F_KIND, F_LABEL, F_PASSWORD, PREFIX};
use crate::bw::scan::{MarkedItem, ValueSource, normalize_collection};
use crate::core_ports::random::OsRandom;
use crate::model::{Attributes, CollectionData, ItemData, LOGIN_COLLECTION, now};
use crate::prompter::one_line;

/// Sends per registry write: the first one and up to two re-applications
/// after an out-of-date rejection.
const ATTEMPTS: usize = sync::ATTEMPTS;
const PLAIN: &str = "text/plain";
const NS: &Namespace = &Namespace::BWSS;
const REGISTRY_UNREADABLE: &str =
    "the collection registry cannot be read; collections cannot be changed until it is fixed";
/// Bitwarden's limit on encrypted notes.
const MAX_NOTES_ENC: usize = 10_000;
/// Metadata only the server sends, dropped from an update body (data model §6.3).
const RESPONSE_ONLY: [&str; 11] = [
    "id",
    "revisionDate",
    "creationDate",
    "deletedDate",
    "object",
    "edit",
    "viewPassword",
    "permissions",
    "collectionIds",
    "attachments",
    "organizationUseTotp",
];

/// The attributes an app set: derived ones (`bwss:*`) are never stored.
pub(crate) fn own_attributes(a: &Attributes) -> Attributes {
    a.iter().filter(|(k, _)| !k.starts_with(PREFIX)).map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// The core's name of a value source.
pub(crate) fn core_source(s: ValueSource) -> CoreSource {
    match s {
        ValueSource::Field => CoreSource::Field,
        ValueSource::BwssNotes => CoreSource::Notes,
        ValueSource::NoteBody => CoreSource::NoteBody,
        ValueSource::LoginPassword => CoreSource::LoginPassword,
    }
}

fn text(name: &str, value: &str) -> FieldSet {
    FieldSet { name: name.to_owned(), value: Zeroizing::new(value.to_owned()), hidden: false }
}

/// The op that turns `old` (as read) into `new`: only what differs. ACL
/// lines are added as a union with what the server holds when the op is
/// sent (data model §3.1, owner's decision 7).
pub(crate) fn plan_put(old: Option<&MarkedItem>, new: &ItemData) -> Op {
    let Some(old) = old else {
        let mut item = new.clone();
        item.attributes = own_attributes(&new.attributes);
        item.collection = normalize_collection(&new.collection);
        // The keyring folder is found, or made, when the create is sent.
        return Op::Create(new_item_of(&item, None));
    };
    let mut set = Vec::new();
    let mut remove = Vec::new();
    if new.label != old.item.label {
        set.push(text(F_LABEL, &new.label));
    }
    let attributes = own_attributes(&new.attributes);
    if attributes != own_attributes(&old.item.attributes) {
        // The attribute set is replaced as a whole (§5.3).
        remove.push(F_ATTR.to_owned());
        set.extend(attributes.iter().map(|(k, v)| text(&format!("{F_ATTR}{k}"), v)));
    }
    let collection = normalize_collection(&new.collection);
    if collection != old.item.collection {
        if collection == LOGIN_COLLECTION {
            remove.push(F_COLLECTION.to_owned());
        } else {
            set.push(text(F_COLLECTION, &collection));
        }
    }
    let content_type = if new.content_type.is_empty() { PLAIN } else { new.content_type.as_str() };
    if content_type != old.item.content_type {
        if content_type == PLAIN {
            remove.push(F_CONTENT_TYPE.to_owned());
        } else {
            set.push(text(F_CONTENT_TYPE, content_type));
        }
    }
    let lines: Vec<Zeroizing<String>> =
        new.acl.iter().filter(|l| !old.item.acl.contains(l)).map(|l| Zeroizing::new(l.clone())).collect();
    let append_lines =
        if lines.is_empty() { Vec::new() } else { vec![LineAppend { name: F_ACL.into(), lines, hidden: true }] };
    let value = if new.secret == old.item.secret {
        ValueChange::Keep
    } else {
        ValueChange::Set {
            source: core_source(old.source),
            secret: new.secret.clone(),
            base_mark: old.mark,
            owned: false,
        }
    };
    Op::Patch(Patch {
        id: old.item.id.clone(),
        cipher_id: Some(old.cipher_id.clone()).filter(|c| c != QUEUED),
        organization_id: None,
        base_revision: old.revision_date.clone(),
        set,
        remove,
        append_lines,
        value,
        answer: None,
    })
}

pub(super) fn is_empty(p: &Patch) -> bool {
    p.set.is_empty() && p.remove.is_empty() && p.append_lines.is_empty() && matches!(p.value, ValueChange::Keep)
}

/// The value source and mark of the cached server copy of an item.
pub(super) type Base = (CoreSource, [u8; 32]);

/// Queues `op` with the core's rules: a patch merges into the item's last
/// queued patch, a delete cancels a queued create. `server` is the base of
/// the cached server copy of the patched item.
pub(super) fn push_op(queue: &mut Vec<Op>, op: Op, server: Option<Base>) -> Undo {
    let id = target(&op).to_owned();
    // Only the ops of this item can change: they alone are kept for an undo.
    let saved = queue.iter().enumerate().filter(|(_, o)| target(o) == id).map(|(i, o)| (i, o.clone())).collect();
    sync::enqueue(queue, NS, op, server);
    Undo { id, saved }
}

/// How to take back a `push_op`, without copying the whole queue: the ops of
/// its item as they were, at their places.
pub(super) struct Undo {
    id: String,
    saved: Vec<(usize, Op)>,
}

impl Undo {
    pub(super) fn apply(self, queue: &mut Vec<Op>) {
        queue.retain(|o| target(o) != self.id);
        // The other ops kept their order: each one goes back where it was.
        for (i, op) in self.saved {
            queue.insert(i.min(queue.len()), op);
        }
    }
}

/// Extra `bwss status` lines: what the user may want to fix.
pub(super) fn status_lines(built: &Built, derive: bool) -> Vec<String> {
    let mut lines = Vec::new();
    for (id, losers) in &built.duplicates {
        lines.push(format!("duplicate id {id}: {} items ignored", losers.len()));
    }
    // Items an app could not tell apart: one collection, one attribute set.
    // Items without attributes are found by their derived ones instead, or
    // by `bwss:id` alone while those are off (ADR 0015).
    let mut groups: BTreeMap<(&str, Attributes), Vec<(&str, &str)>> = BTreeMap::new();
    let mut bare = Vec::new();
    for m in built.marked.values() {
        let attributes = own_attributes(&m.item.attributes);
        if !attributes.is_empty() {
            groups.entry((&m.item.collection, attributes)).or_default().push((&m.item.label, &m.item.id));
        } else if !derive {
            bare.push(m.item.id.as_str());
        }
    }
    if !bare.is_empty() {
        bare.sort_unstable();
        lines.push(format!(
            "no bwss:attr:* field, so apps find these by bwss:id only while derived attributes are off \
             (`bwss derive on`, or add attributes with `dybw mark`): {}",
            bare.join(", ")
        ));
    }
    for mut group in groups.into_values().filter(|g| g.len() > 1) {
        group.sort_by_key(|&(_, id)| id);
        let list: Vec<String> = group.iter().map(|(label, id)| format!("{label} ({id})")).collect();
        lines.push(format!("possible duplicates: {}", list.join(", ")));
    }
    for (_, why) in &built.skipped {
        lines.push(format!("skipped: {why}"));
    }
    if built.registry_unreadable {
        lines.push(REGISTRY_UNREADABLE.to_owned());
    }
    lines
}

/// `bwss status` lines for the queued ops that wait on the user or on an item.
pub(super) fn queue_lines(state: &Unlocked, queue: &Queue) -> Vec<String> {
    // Labels come from the vault: one line, no control characters, reaches the terminal.
    let label = |id: &str| one_line(state.built.marked.get(id).map_or(id, |m| m.item.label.as_str()));
    let mut lines: Vec<String> = state
        .questions
        .iter()
        .map(|(id, q)| {
            format!(
                "waits for your answer: {} ({id}); answer with `bwss answer {id} login|separate|cancel`",
                question_text(&label(id), *q)
            )
        })
        .collect();
    lines.extend(state.stuck.iter().map(|(id, why)| {
        format!("a queued change of {} ({id}) waits: {}; it is kept", label(id), uninspectable_text(*why))
    }));
    let held: Vec<&str> =
        state.rollbacks.iter().map(|r| r.id.as_str()).filter(|id| queue.ops.iter().any(|o| target(o) == *id)).collect();
    if !held.is_empty() {
        lines.push(format!(
            "queued changes wait while the server holds an older copy than this device: {}",
            held.join(", ")
        ));
    }
    lines
}

/// A collection id for a new collection called `label`: lowercase, never
/// one that reads as `login`, never one in use.
fn new_collection_id(label: &str, taken: impl Fn(&str) -> bool) -> String {
    let base = label.trim().to_lowercase();
    let base = if base.is_empty() { "collection".to_owned() } else { base };
    let mut id = base.clone();
    let mut n = 1;
    while normalize_collection(&id) != id || taken(&id) {
        n += 1;
        id = format!("{base}-{n}");
    }
    id
}

/// What an op did on the server.
#[derive(Debug)]
pub(crate) enum Effect {
    /// Nothing to record: an empty patch, an item already gone or created.
    Nothing,
    /// The server's copy after the write.
    Saved(Value),
    /// The cipher left the keyring: moved to the trash, or stripped and kept
    /// for what the user has in it. The cache drops it until the next sync.
    Trashed(String),
}

#[derive(Debug)]
pub(super) enum Failure {
    Locked,
    /// Try again later.
    Transient(String),
    /// The target cannot be read now: the op must never be dropped (R12a).
    Wait(String),
    /// Out of date on every attempt: the app is told to try again; a queued
    /// op stays queued.
    Busy(String),
    /// The value source changed on the server (§5.6).
    Conflict,
    /// The target was trashed, deleted or unmarked elsewhere.
    Gone,
    /// The write needs the user's answer first (ADR 0016).
    Ask(HistoryQuestion),
    /// Refused for good; `cid` is the cipher to reread.
    Permanent {
        why: String,
        cid: Option<String>,
    },
}

/// What a write error says to the user, in bwss's words where it had them.
fn write_text(e: &WriteError) -> String {
    match e {
        WriteError::TooLong => "secret is too large for a Bitwarden item".into(),
        WriteError::NotesTaken => "secret does not fit its field and the notes hold the user's text".into(),
        e => e.to_string(),
    }
}

fn write_failure(e: WriteError, cid: &str) -> Failure {
    match e {
        WriteError::SourceChanged => Failure::Conflict,
        WriteError::Gone | WriteError::Unmarked => Failure::Gone,
        WriteError::Ask(q) => Failure::Ask(q),
        WriteError::Uninspectable(why) => Failure::Wait(format!("{cid}: {}", uninspectable_text(why))),
        WriteError::Crypto(_) => Failure::Wait(format!("{cid}: the item cannot be read")),
        e @ (WriteError::Unsupported | WriteError::BadClock) => Failure::Wait(format!("{cid}: {e}")),
        e @ (WriteError::TooLong | WriteError::NotesTaken | WriteError::ReadOnly | WriteError::BinaryNotSupported) => {
            Failure::Permanent { why: write_text(&e), cid: None }
        }
    }
}

/// A failed request: an ended session drops the client, so the next sync
/// logs in again, and the op is kept.
fn api_failure(e: ApiError, cid: Option<&str>, client: &mut Option<CoreClient>) -> Failure {
    if e.is_transient() {
        return Failure::Transient(e.to_string());
    }
    match e {
        ApiError::Http { status: 401, .. } | ApiError::NotLoggedIn | ApiError::NotSynced => {
            *client = None;
            Failure::Transient(e.to_string())
        }
        e => Failure::Permanent { why: e.to_string(), cid: cid.map(str::to_owned) },
    }
}

fn sync_failure(e: SyncWriteError, cid: Option<&str>, client: &mut Option<CoreClient>) -> Failure {
    match e {
        SyncWriteError::Write(w) => write_failure(w, cid.unwrap_or_default()),
        SyncWriteError::Api(a) => api_failure(a, cid, client),
        e @ SyncWriteError::StillChanging => Failure::Busy(e.to_string()),
        e @ SyncWriteError::OwnerChanged => Failure::Wait(e.to_string()),
        SyncWriteError::MissingId => Failure::Gone,
    }
}

fn not_connected() -> Failure {
    Failure::Transient("not logged in to Bitwarden yet".into())
}

fn id_of(cipher: &Value) -> &str {
    cipher.get("id").and_then(Value::as_str).unwrap_or_default()
}

fn live(cipher: &Value) -> bool {
    cipher.get("deletedDate").is_none_or(Value::is_null)
}

/// The cached server copy of item `id`: the cipher the build served it from
/// (the bound winner, ADR 0019), never a duplicate, held or newer-format one.
fn locate(state: &Unlocked, id: &str) -> Result<Value, Failure> {
    let m = state.built.marked.get(id).filter(|m| m.cipher_id != QUEUED).ok_or(Failure::Gone)?;
    let cipher = ciphers(&state.sync).iter().find(|c| id_of(c) == m.cipher_id && live(c)).ok_or(Failure::Gone)?;
    // An item held as last read (§3.4) is still there, but cannot be written now.
    if matches!(core_scan(cipher, NS, &state.core_keys, &Organizations::None), CoreScan::Uninspectable(_)) {
        return Err(Failure::Wait(format!("item {id} cannot be read now")));
    }
    Ok(cipher.clone())
}

/// The base of the cached server copy of item `id`, when it can be read.
fn server_base(state: &Unlocked, id: &str) -> Option<Base> {
    let cipher = locate(state, id).ok()?;
    let CoreScan::Marked(m) = core_scan(&cipher, NS, &state.core_keys, &Organizations::None) else { return None };
    Some((m.source, m.mark))
}

/// This device's record of what it wrote to item `id`, when it belongs to
/// cipher `cid` (ADR 0016).
fn record_for(records: &BTreeMap<String, WriteRecord>, id: &str, cid: &str) -> WriteRecord {
    records.get(id).filter(|r| r.cipher_id.as_deref().is_none_or(|c| c == cid)).cloned().unwrap_or_default()
}

/// The registry note to write to: the one with the lowest cipher id.
fn registry_note(state: &Unlocked) -> Option<Value> {
    let list = ciphers(&state.sync);
    state
        .built
        .registry_ciphers
        .iter()
        .filter_map(|cid| list.iter().find(|c| id_of(c) == cid && live(c)))
        .min_by(|a, b| id_of(a).cmp(id_of(b)))
        .cloned()
}

/// `json` as encrypted notes under `key`, refused over Bitwarden's limit.
fn sealed_notes(key: &CoreKey, json: &str) -> Result<Value, Failure> {
    if key.encrypted_str_len(json.len()) > MAX_NOTES_ENC {
        return Err(Failure::Permanent { why: write_text(&WriteError::TooLong), cid: None });
    }
    key.encrypt_str(json, &OsRandom).map(Value::String).map_err(|e| Failure::Transient(e.to_string()))
}

/// Whether `note` still carries the registry's `bwss:id`, and whether it has
/// a `bwss:password` field; `Err` when it cannot be read.
fn registry_marks(note: &Value, keys: &CoreKeys) -> Result<(bool, bool), Failure> {
    let cid = id_of(note);
    let unreadable = |e: dybw_core::crypto::CryptoError| Failure::Wait(format!("{cid}: {e}"));
    let key = core_fields::item_key(note, &keys.user).map_err(unreadable)?;
    let names = core_fields::field_names(note, &key).map_err(unreadable)?;
    let marked = match core_fields::first_index(&names, F_ID) {
        Some(i) => core_fields::field_value(note, i, &key).map_err(unreadable)?.trim() == REGISTRY_ID,
        None => false,
    };
    Ok((marked, core_fields::first_index(&names, F_PASSWORD).is_some()))
}

/// The update body that writes `json` into the registry note's notes.
fn registry_update(note: &Value, json: &str, keys: &CoreKeys) -> Result<Map<String, Value>, Failure> {
    let cid = id_of(note);
    let key = core_fields::item_key(note, &keys.user).map_err(|e| Failure::Wait(format!("{cid}: {e}")))?;
    let notes = sealed_notes(&key, json)?;
    let mut body: Map<String, Value> = note
        .as_object()
        .map(|o| o.iter().filter(|(k, _)| !RESPONSE_ONLY.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())))
        .map(Iterator::collect)
        .unwrap_or_default();
    body.insert("notes".into(), notes);
    if !body.get("passwordHistory").is_some_and(Value::is_array) {
        body.insert("passwordHistory".into(), json!([]));
    }
    body.insert("lastKnownRevisionDate".into(), note.get("revisionDate").cloned().unwrap_or(Value::Null));
    Ok(body)
}

/// The create body of a registry note (design §4): a personal secure note
/// marked `_collections` and `collections`, whose notes hold `json`.
fn registry_new(json: &str, folder: &str, keys: &CoreKeys) -> Result<Map<String, Value>, Failure> {
    let user = &keys.user;
    let enc = |t: &str| user.encrypt_str(t, &OsRandom).map_err(|e| Failure::Transient(e.to_string()));
    let field = |n: &str, v: &str| -> Result<Value, Failure> {
        Ok(json!({ "type": 0, "name": enc(n)?, "value": enc(v)?, "linkedId": null }))
    };
    let body = json!({
        "type": 2, "organizationId": null, "folderId": folder, "name": enc("bwss collections")?,
        "notes": sealed_notes(user, json)?, "login": null, "secureNote": { "type": 0 }, "favorite": false,
        "reprompt": 0, "key": null, "passwordHistory": [],
        "fields": [field(F_ID, REGISTRY_ID)?, field(F_KIND, KIND_COLLECTIONS)?],
    });
    Ok(body.as_object().cloned().unwrap_or_default())
}

/// What the next registry write sends.
enum RegistryPlan {
    Create,
    Update(String, Map<String, Value>),
}

impl Bitwarden {
    async fn with_state<T>(&self, f: impl FnOnce(&Unlocked) -> Result<T, Failure>) -> Result<T, Failure> {
        let guard = self.state.lock().await;
        f(guard.as_ref().ok_or(Failure::Locked)?)
    }

    /// The client, logged in and synced, or why there is none.
    async fn connected(&self) -> Result<MutexGuard<'_, Option<CoreClient>>, Failure> {
        let guard = self.client.lock().await;
        if guard.is_none() {
            return Err(not_connected());
        }
        Ok(guard)
    }

    /// The server's current copy of `cid`.
    async fn refetch(&self, cid: &str) -> Result<Value, Failure> {
        let mut guard = self.connected().await?;
        let Some(client) = guard.as_mut() else { return Err(not_connected()) };
        match client.get_cipher(cid).await {
            Ok(c) => Ok(c),
            Err(ApiError::Http { status: 404, .. }) => Err(Failure::Gone),
            Err(e) => Err(api_failure(e, Some(cid), &mut guard)),
        }
    }

    /// The keyring folder's id; it is created on first need (§5.1).
    pub(super) async fn ensure_keyring_folder(&self) -> Result<String, Failure> {
        let enc = self
            .with_state(|state| match &state.keyring_folder {
                Some(id) => Ok(Err(id.clone())),
                None => state
                    .core_keys
                    .user
                    .encrypt_str(&self.root, &OsRandom)
                    .map(Ok)
                    .map_err(|e| Failure::Transient(e.to_string())),
            })
            .await?;
        let enc = match enc {
            Err(id) => return Ok(id),
            Ok(enc) => enc,
        };
        let folder = {
            let mut guard = self.connected().await?;
            let Some(client) = guard.as_mut() else { return Err(not_connected()) };
            match client.create_folder(&enc).await {
                Ok(f) => f,
                Err(e) => return Err(api_failure(e, None, &mut guard)),
            }
        };
        let id = folder.get("id").and_then(Value::as_str).filter(|id| !id.is_empty()).map(str::to_owned);
        let id = id.ok_or_else(|| Failure::Transient("the server created a folder without an id".into()))?;
        if let Some(s) = self.state.lock().await.as_mut() {
            s.keyring_folder = Some(id.clone());
        }
        Ok(id)
    }

    /// Sends `op` now. `queue` is kept on disk with a write record it adds.
    pub(super) async fn run(&self, queue: &Queue, op: &Op) -> Result<Effect, Failure> {
        match op {
            Op::Create(item) => self.run_create(item).await,
            Op::Patch(patch) => self.run_patch(queue, patch).await,
            Op::Delete { id, .. } => self.run_delete(id).await,
        }
    }

    async fn run_create(&self, item: &core_write::NewItem) -> Result<Effect, Failure> {
        // Accepted before (for example just before a lock): never twice.
        let exists =
            self.with_state(|s| Ok(s.built.marked.get(&item.id).is_some_and(|m| m.cipher_id != QUEUED))).await?;
        if exists {
            return Ok(Effect::Nothing);
        }
        let folder = self.ensure_keyring_folder().await?;
        let keys = self.with_state(|s| Ok(copy_keys(&s.core_keys))).await?;
        let new = core_write::NewItem { folder_id: Some(folder), ..item.clone() };
        let mut guard = self.connected().await?;
        let Some(client) = guard.as_mut() else { return Err(not_connected()) };
        match sync::create(client, NS, &keys, &OsRandom, &new).await {
            Ok(reply) => Ok(Effect::Saved(reply)),
            Err(e) => Err(sync_failure(e, None, &mut guard)),
        }
    }

    async fn run_patch(&self, queue: &Queue, patch: &Patch) -> Result<Effect, Failure> {
        if is_empty(patch) {
            return Ok(Effect::Nothing);
        }
        let (keys, cipher, record) = self
            .with_state(|s| {
                let cipher = locate(s, &patch.id)?;
                let record = record_for(&s.records, &patch.id, id_of(&cipher));
                Ok((copy_keys(&s.core_keys), cipher, record))
            })
            .await?;
        let cid = id_of(&cipher).to_owned();
        let sent = {
            let mut guard = self.connected().await?;
            let Some(client) = guard.as_mut() else { return Err(not_connected()) };
            let now = client.now_ms();
            match sync::update(client, NS, &keys, &record, &OsRandom, now, &cipher, patch).await {
                Ok(sent) => sent,
                Err(e) => return Err(sync_failure(e, Some(&cid), &mut guard)),
            }
        };
        let Some((reply, wrote)) = sent else { return Ok(Effect::Nothing) };
        if let Some(mark) = wrote {
            self.record_login_write(queue, &patch.id, &cid, mark).await;
        }
        Ok(Effect::Saved(reply))
    }

    /// Keeps what this device wrote to a login password (ADR 0016), in the
    /// queue file.
    async fn record_login_write(&self, queue: &Queue, id: &str, cid: &str, mark: [u8; 32]) {
        let mut guard = self.state.lock().await;
        // Locked meanwhile: the next write asks again, the safe direction.
        let Some(state) = guard.as_mut() else { return };
        let record = state.records.entry(id.to_owned()).or_default();
        if record.cipher_id.as_deref() != Some(cid) {
            *record = WriteRecord { cipher_id: Some(cid.to_owned()), ..WriteRecord::default() };
        }
        record_write(record, mark);
        // Logged in `save_queue`: a write that is not recorded asks again.
        let _ = self.keep_queue(queue, state);
    }

    /// Design §5.4: strip, save, then trash only what the server's answer
    /// shows to be bwss's alone.
    async fn run_delete(&self, id: &str) -> Result<Effect, Failure> {
        let found = self
            .with_state(|s| match locate(s, id) {
                Ok(cipher) => Ok(Some((copy_keys(&s.core_keys), cipher))),
                Err(Failure::Gone) => Ok(None),
                Err(f) => Err(f),
            })
            .await?;
        let Some((keys, cipher)) = found else { return Ok(Effect::Nothing) };
        let cid = id_of(&cipher).to_owned();
        let outcome = {
            let mut guard = self.connected().await?;
            let Some(client) = guard.as_mut() else { return Err(not_connected()) };
            match sync::delete(client, NS, &keys, &OsRandom, &cipher, id).await {
                Ok(outcome) => outcome,
                Err(e) => return Err(sync_failure(e, Some(&cid), &mut guard)),
            }
        };
        Ok(match outcome {
            DeleteOutcome::Trashed | DeleteOutcome::KeptForeign => Effect::Trashed(cid),
            DeleteOutcome::Nothing => Effect::Nothing,
            DeleteOutcome::Stripped { trash } => {
                tracing::warn!(cipher = %cid, "the item left the keyring but could not be moved to the trash: {trash}");
                Effect::Trashed(cid)
            }
            DeleteOutcome::Unreadable(e) => {
                tracing::warn!(cipher = %cid, "the stripped item cannot be inspected ({e}); it is kept");
                Effect::Trashed(cid)
            }
        })
    }

    /// Read, merge, put, write (§4): the registry note is merged with the
    /// server's copy entry by entry, never overwritten.
    async fn run_registry(&self, collection: &str, entry: &Entry) -> Result<Effect, Failure> {
        // `Some(None)`: the note is known to be gone.
        let mut fresh: Option<Option<Value>> = None;
        for _ in 0..ATTEMPTS {
            let plan = self
                .with_state(|state| {
                    if state.built.registry_unreadable {
                        return Err(Failure::Wait(REGISTRY_UNREADABLE.into()));
                    }
                    let note = fresh.take().unwrap_or_else(|| registry_note(state));
                    let Some(note) = note.filter(live) else { return Ok(RegistryPlan::Create) };
                    let (marked, password) = registry_marks(&note, &state.core_keys)?;
                    if !marked {
                        // No longer a registry note: start a new one.
                        return Ok(RegistryPlan::Create);
                    }
                    let mut merged = match read_registry(&note, &state.core_keys) {
                        Ok(Some(r)) => r,
                        Ok(None) => return Ok(RegistryPlan::Create),
                        Err(_) => return Err(Failure::Wait(REGISTRY_UNREADABLE.into())),
                    };
                    if password {
                        return Err(Failure::Wait("the collection registry note has a bwss:password field".into()));
                    }
                    merged.merge(&state.built.registry);
                    // Merged, never put: a newer entry from another device wins.
                    merged.merge(&Registry(BTreeMap::from([(collection.to_owned(), entry.clone())])));
                    let body = registry_update(&note, &merged.to_json(), &state.core_keys)?;
                    Ok(RegistryPlan::Update(id_of(&note).to_owned(), body))
                })
                .await?;
            let (cid, body) = match plan {
                RegistryPlan::Update(cid, body) => (cid, body),
                RegistryPlan::Create => return self.create_registry(collection, entry).await,
            };
            let sent = {
                let mut guard = self.connected().await?;
                let Some(client) = guard.as_mut() else { return Err(not_connected()) };
                match client.update_cipher(&cid, body).await {
                    Ok(reply) => Ok(reply),
                    Err(e) if e.is_out_of_date() => Err(None),
                    Err(e) => Err(Some(api_failure(e, Some(&cid), &mut guard))),
                }
            };
            match sent {
                Ok(reply) => return Ok(Effect::Saved(reply)),
                Err(Some(f)) => return Err(f),
                Err(None) => match self.refetch(&cid).await {
                    Ok(c) => fresh = Some(Some(c)),
                    Err(Failure::Gone) => fresh = Some(None),
                    Err(f) => return Err(f),
                },
            }
        }
        Err(Failure::Busy("the collection registry keeps changing elsewhere".into()))
    }

    async fn create_registry(&self, collection: &str, entry: &Entry) -> Result<Effect, Failure> {
        let folder = self.ensure_keyring_folder().await?;
        let body = self
            .with_state(|state| {
                if state.built.registry_unreadable {
                    return Err(Failure::Wait(REGISTRY_UNREADABLE.into()));
                }
                let mut registry = state.built.registry.clone();
                registry.put(collection, entry.clone());
                registry_new(&registry.to_json(), &folder, &state.core_keys)
            })
            .await?;
        let mut guard = self.connected().await?;
        let Some(client) = guard.as_mut() else { return Err(not_connected()) };
        match client.create_cipher(body).await {
            Ok(reply) => Ok(Effect::Saved(reply)),
            Err(e) => Err(api_failure(e, None, &mut guard)),
        }
    }

    // --- live ops ------------------------------------------------------------

    /// Clears the in-memory queue once the keyring is locked: it is on disk,
    /// sealed, and its secrets must leave memory with the keys (R12b).
    pub(super) async fn forget_if_locked(&self, queue: &mut Queue) {
        if self.state.lock().await.is_none() {
            queue.clear();
        }
    }

    /// Runs a live op, or queues it while an op of the same item is queued,
    /// the server cannot be reached, or the server holds an older copy of the
    /// item than this device (ADR 0019: never written over).
    async fn submit_locked(&self, queue: &mut Queue, op: Op) -> Result<(), BackendError> {
        let held = {
            let guard = self.state.lock().await;
            guard.as_ref().ok_or(BackendError::Locked)?.rollbacks.iter().any(|r| r.id == target(&op))
        };
        // Keep order per item: while one of its ops is queued, the next one
        // queues behind it; other items' writes go on (§8.3).
        let behind = queue.ops.iter().any(|o| target(o) == target(&op));
        if behind || held || !self.can_write().await {
            return self.enqueue(queue, op).await;
        }
        match self.run(queue, &op).await {
            Ok(effect) => self.settle(queue, effect).await,
            Err(Failure::Transient(why)) => {
                tracing::info!("offline ({why}); the change is queued");
                self.enqueue(queue, op).await
            }
            Err(f) => Err(self.refuse(queue, f).await),
        }
    }

    /// `submit_locked` for a collection registry change.
    async fn submit_registry(&self, queue: &mut Queue, op: RegistryOp) -> Result<(), BackendError> {
        // Only behind a queued collection change: the registry keeps its order.
        if !queue.registry.is_empty() || !self.can_write().await {
            return self.enqueue_registry(queue, op).await;
        }
        match self.run_registry(&op.collection, &op.entry).await {
            Ok(effect) => self.settle(queue, effect).await,
            Err(Failure::Transient(why)) => {
                tracing::info!("offline ({why}); the change is queued");
                self.enqueue_registry(queue, op).await
            }
            Err(f) => Err(self.refuse(queue, f).await),
        }
    }

    /// The error an app gets for a live op that failed for good.
    async fn refuse(&self, queue: &Queue, f: Failure) -> BackendError {
        let (error, reread) = refusal(f);
        if let Some(cid) = reread {
            self.rescan(queue, &cid).await;
        }
        error
    }

    pub(super) async fn settle(&self, queue: &Queue, effect: Effect) -> Result<(), BackendError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        self.absorb(state, queue, effect);
        Ok(())
    }

    /// Rereads `cid` from the server, so the local view returns to the truth.
    async fn rescan(&self, queue: &Queue, cid: &str) {
        let effect = match self.refetch(cid).await {
            Ok(c) => Effect::Saved(c),
            Err(Failure::Gone) => Effect::Trashed(cid.to_owned()),
            Err(f) => {
                tracing::info!(cipher = %cid, "could not reread the item: {f:?}");
                return;
            }
        };
        if let Err(e) = self.settle(queue, effect).await {
            tracing::debug!("not rescanned: {e}");
        }
    }

    /// Queues `op` behind the others, keeps it on disk and shows it. An op
    /// that could never be written fails here instead of later.
    async fn enqueue(&self, queue: &mut Queue, op: Op) -> Result<(), BackendError> {
        let mut guard = self.state.lock().await;
        // Locked meanwhile: the op, and its secret, is never kept (R12b).
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        check_queueable(state, queue, &op)?;
        let server = match &op {
            Op::Patch(p) => server_base(state, &p.id),
            _ => None,
        };
        let undo = push_op(&mut queue.ops, op, server);
        // Not on disk, not durable: the app is told, and nothing is kept.
        if let Err(e) = self.keep_queue(queue, state) {
            undo.apply(&mut queue.ops);
            return Err(BackendError::Unavailable(format!("the change cannot be queued on disk: {e}")));
        }
        self.rebuild(state, queue);
        Ok(())
    }

    async fn enqueue_registry(&self, queue: &mut Queue, op: RegistryOp) -> Result<(), BackendError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        queue.registry.push(op);
        if let Err(e) = self.keep_queue(queue, state) {
            queue.registry.pop();
            return Err(BackendError::Unavailable(format!("the change cannot be queued on disk: {e}")));
        }
        self.rebuild(state, queue);
        Ok(())
    }

    /// Stores `item`. `answer` answers the history question an earlier try
    /// of this write asked (ADR 0016).
    pub(super) async fn put_locked(
        &self,
        queue: &mut Queue,
        item: &ItemData,
        answer: Option<(HistoryQuestion, HistoryAnswer)>,
    ) -> Result<(), BackendError> {
        let old = {
            let guard = self.state.lock().await;
            guard.as_ref().ok_or(BackendError::Locked)?.built.marked.get(&item.id).cloned()
        };
        if old.as_ref().is_some_and(|m| m.cipher_id == QUEUED) {
            // Not on the server yet: the queued create carries the new version.
            let Op::Create(new) = plan_put(None, item) else { unreachable!("no old item gives a create") };
            {
                let guard = self.state.lock().await;
                let state = guard.as_ref().ok_or(BackendError::Locked)?;
                check_queueable(state, queue, &Op::Create(new.clone()))?;
            }
            for op in &mut queue.ops {
                if let Op::Create(queued) = op
                    && queued.id == new.id
                {
                    *queued = core_write::NewItem { folder_id: queued.folder_id.take(), ..new.clone() };
                }
            }
            return self.queue_changed(queue).await;
        }
        match plan_put(old.as_ref(), item) {
            Op::Patch(p) if is_empty(&p) => Ok(()),
            Op::Patch(p) => self.submit_locked(queue, Op::Patch(Patch { answer, ..p })).await,
            op => self.submit_locked(queue, op).await,
        }
    }

    pub(super) async fn delete_locked(&self, queue: &mut Queue, id: &str) -> Result<(), BackendError> {
        let target = {
            let guard = self.state.lock().await;
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            state.built.marked.get(id).map(|m| (m.cipher_id.clone(), m.revision_date.clone()))
        };
        let Some((cid, base_revision)) = target else { return Ok(()) };
        if cid == QUEUED {
            // Never reached the server: drop it from the queue.
            queue.ops.retain(|op| target_is_not(op, id));
            return self.queue_changed(queue).await;
        }
        let op = Op::Delete { id: id.to_owned(), base_revision, cipher_id: Some(cid), organization_id: None };
        self.submit_locked(queue, op).await
    }

    pub(super) async fn create_collection_locked(
        &self,
        queue: &mut Queue,
        label: &str,
    ) -> Result<CollectionData, BackendError> {
        let (id, entry) = {
            let guard = self.state.lock().await;
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            // R10: never write over a registry that cannot be read.
            if state.built.registry_unreadable {
                return Err(BackendError::Rejected(REGISTRY_UNREADABLE.into()));
            }
            let shown = &state.built.snapshot.collections;
            let id = new_collection_id(label, |id| shown.iter().any(|c| c.id == id));
            // A newer `created` wins over an earlier tombstone in a merge.
            let after = registry_with_queue(&state.built.registry, queue).0.get(&id).map_or(0, |e| e.created + 1);
            (id, Entry { label: label.to_owned(), created: now().max(after), deleted: false })
        };
        let created = entry.created;
        self.submit_registry(queue, RegistryOp { collection: id.clone(), entry }).await?;
        Ok(CollectionData { id, label: label.to_owned(), created, modified: created })
    }

    /// Applies the delete rule to every item of the collection, then leaves
    /// a tombstone in the registry (§4). `authorized` are the items the
    /// caller authorized: an item that joined the collection since is never
    /// deleted, and the whole delete is refused instead.
    pub(super) async fn delete_collection_locked(
        &self,
        queue: &mut Queue,
        id: &str,
        authorized: &[String],
    ) -> Result<(), BackendError> {
        let (items, tombstone) = {
            let guard = self.state.lock().await;
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            if state.built.registry_unreadable {
                return Err(BackendError::Rejected(REGISTRY_UNREADABLE.into()));
            }
            let mut items: Vec<String> =
                state.built.marked.values().filter(|m| m.item.collection == id).map(|m| m.item.id.clone()).collect();
            if items.iter().any(|i| !authorized.contains(i)) {
                return Err(BackendError::Rejected("the collection changed meanwhile; try again".into()));
            }
            items.sort();
            let shown = registry_with_queue(&state.built.registry, queue);
            let tombstone = shown.0.get(id).filter(|e| !e.deleted).map(|e| Entry { deleted: true, ..e.clone() });
            (items, tombstone)
        };
        for item in items {
            self.delete_locked(queue, &item).await?;
        }
        if let Some(entry) = tombstone {
            self.submit_registry(queue, RegistryOp { collection: id.to_owned(), entry }).await?;
        }
        Ok(())
    }

    // --- the queue -------------------------------------------------------------

    /// Replays queued writes. The ops of an item that has to wait stay
    /// queued, in order; a cause every op shares stops the flush.
    pub(super) async fn flush_queue(&self) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        let result = self.flush_locked(&mut queue).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    async fn flush_locked(&self, queue: &mut Queue) -> Result<(), BackendError> {
        if queue.is_empty() || !self.can_write().await {
            return Ok(());
        }
        if queue.ops.iter().any(|o| matches!(o, Op::Create(n) if n.folder_id.is_none())) {
            let folder = self.ensure_keyring_folder().await.map_err(|f| refusal(f).0)?;
            for op in &mut queue.ops {
                if let Op::Create(n) = op
                    && n.folder_id.is_none()
                {
                    n.folder_id = Some(folder.clone());
                }
            }
        }
        // queue.json must lose every op the server accepted, even when the
        // keyring locks during the flush (R12c): these copies live until the
        // flush ends.
        let (keys, seal, sync, mut records, held) = self
            .with_state(|s| {
                let held: HashSet<String> = s.rollbacks.iter().map(|r| r.id.clone()).collect();
                let seal = (queue_key(&s.core_keys.user), s.user_key_id.clone());
                Ok((copy_keys(&s.core_keys), seal, s.sync.clone(), s.records.clone(), held))
            })
            .await
            .map_err(|f| refusal(f).0)?;
        let start = queue.len();
        // ADR 0019: an item the server sent older than this device's copy
        // is never written over; its ops wait until that is settled.
        let report = {
            let mut guard = self.client.lock().await;
            // The session ended meanwhile: the next sync logs in again and flushes.
            let Some(client) = guard.as_mut() else { return Err(refusal(not_connected()).0) };
            let (mut ops, waiting): (Vec<Op>, Vec<Op>) =
                std::mem::take(&mut queue.ops).into_iter().partition(|o| !held.contains(target(o)));
            let now = client.now_ms();
            let report = sync::flush(&mut ops, client, NS, &keys, &mut records, &OsRandom, now, &sync).await;
            ops.extend(waiting);
            queue.ops = ops;
            report
        };
        let mut changed = log_report(&report);
        let _ = self.save_queue(queue, &records, &seal.0, &seal.1);
        let stopped = self.flush_registry(queue, &records, &seal, &mut changed).await;
        // The queue moved on: a migrated one's old file would replay what left it.
        if queue.len() < start {
            self.drop_v3_backup();
        }
        {
            let mut guard = self.state.lock().await;
            let state = guard.as_mut().ok_or(BackendError::Locked)?;
            state.records = records;
            state.questions.clone_from(&report.questions);
            state.stuck.clone_from(&report.stuck);
            self.rebuild(state, queue);
        }
        if changed && let Err(e) = self.pull(queue, &[]).await {
            tracing::info!("the vault is read again at the next sync: {e}");
        }
        stopped?;
        match report.kept.first() {
            Some((_, why)) => Err(BackendError::Unavailable(format!("a queued change waits: {why}"))),
            None => Ok(()),
        }
    }

    /// Replays the queued collection changes in order; stops at the first
    /// one that has to wait.
    async fn flush_registry(
        &self,
        queue: &mut Queue,
        records: &Records,
        (key, user_key_id): &(CoreKey, String),
        changed: &mut bool,
    ) -> Result<(), BackendError> {
        while let Some(op) = queue.registry.first() {
            let rescan = match self.run_registry(&op.collection, &op.entry).await {
                Ok(effect) => {
                    queue.registry.remove(0);
                    let _ = self.save_queue(queue, records, key, user_key_id);
                    self.settle(queue, effect).await?;
                    *changed = true;
                    continue;
                }
                Err(f @ (Failure::Locked | Failure::Transient(_) | Failure::Wait(_) | Failure::Busy(_))) => {
                    let (e, _) = refusal(f);
                    tracing::warn!("a queued collection change waits: {e}");
                    return Err(e);
                }
                // Refused for good: dropped, and the note is read again.
                Err(f) => refusal(f).1,
            };
            queue.registry.remove(0);
            let _ = self.save_queue(queue, records, key, user_key_id);
            *changed = true;
            if let Some(cid) = rescan {
                self.rescan(queue, &cid).await;
            }
        }
        Ok(())
    }

    /// The user's confirmed answer to the question the queued change of `id`
    /// waits on (ADR 0016), kept on disk at once. Only an answer to that very
    /// question counts. A cancel drops the value change only; the op goes
    /// when nothing else is left in it.
    pub(super) async fn answer_locked(
        &self,
        queue: &mut Queue,
        id: &str,
        question: HistoryQuestion,
        answer: Option<HistoryAnswer>,
    ) -> Result<(), BackendError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        let none = || BackendError::Rejected(format!("no queued change of {id} waits for that answer"));
        if !state.questions.contains(&(id.to_owned(), question)) {
            return Err(none());
        }
        // Only a patch writes to a login password, so only a patch is asked about.
        let at = queue.ops.iter().position(|o| target(o) == id).ok_or_else(none)?;
        let Some(Op::Patch(p)) = queue.ops.get_mut(at) else { return Err(none()) };
        let before = Op::Patch(p.clone());
        let emptied = match answer {
            Some(a) => {
                p.answer = Some((question, a));
                false
            }
            None => {
                tracing::warn!(id = %id, "a queued secret change was cancelled by `bwss answer`");
                p.value = ValueChange::Keep;
                is_empty(p)
            }
        };
        if emptied {
            queue.ops.remove(at);
        }
        if let Err(e) = self.keep_queue(queue, state) {
            // Not on disk: the answer is not kept in memory either.
            if emptied {
                queue.ops.insert(at, before);
            } else if let Some(slot) = queue.ops.get_mut(at) {
                *slot = before;
            }
            return Err(BackendError::Unavailable(format!("the answer cannot be kept on disk: {e}")));
        }
        state.questions.retain(|(i, _)| i != id);
        self.rebuild(state, queue);
        Ok(())
    }
}

/// Logs what a flush did; whether the server may hold something new.
fn log_report(report: &FlushReport) -> bool {
    for (id, e) in &report.dropped {
        match e {
            WriteError::SourceChanged => tracing::warn!(
                "dropping a queued secret change of {id}: the secret was changed elsewhere; the item's other \
                 queued changes are kept"
            ),
            e => tracing::warn!("dropping a queued change of {id}: {}", write_text(e)),
        }
    }
    for (id, e) in &report.refused {
        tracing::warn!("dropping a queued change of {id} the server refused: {e}");
    }
    for (id, why) in &report.kept {
        tracing::warn!("a queued change of {id} waits: {why}");
    }
    for (id, q) in &report.questions {
        tracing::info!("a queued change of {id} waits for an answer: {}", q.code());
    }
    for (id, why) in &report.stuck {
        tracing::warn!("a queued change of {id} waits: {}", uninspectable_text(*why));
    }
    !report.done.is_empty() || !report.dropped.is_empty() || !report.refused.is_empty()
}

/// What an app is told when a live op failed, and the cipher to reread from
/// the server so the local view returns to the truth.
fn refusal(f: Failure) -> (BackendError, Option<String>) {
    match f {
        Failure::Locked => (BackendError::Locked, None),
        Failure::Transient(why) => (BackendError::Unavailable(why), None),
        Failure::Wait(why) => (BackendError::Unavailable(format!("{why}; try again later")), None),
        Failure::Busy(why) => (BackendError::Unavailable(format!("{why}; try again")), None),
        Failure::Conflict => (BackendError::Conflict("the secret was changed elsewhere".into()), None),
        Failure::Gone => (BackendError::Rejected("the item was deleted elsewhere".into()), None),
        Failure::Ask(q) => (BackendError::Ask(q), None),
        Failure::Permanent { why, cid } => {
            tracing::warn!("a change was refused: {why}");
            (BackendError::Rejected(why), cid)
        }
    }
}

fn target_is_not(op: &Op, id: &str) -> bool {
    target(op) != id
}

/// What a write error means for an op about to be queued: a size problem
/// refuses it now, since it could never be written; everything else is
/// decided against the server when the op runs.
fn queueable(e: WriteError) -> Result<(), BackendError> {
    match e {
        WriteError::TooLong | WriteError::NotesTaken => Err(BackendError::Rejected(write_text(&e))),
        _ => Ok(()),
    }
}

/// The server copy of item `id` in a queued view. A patch is never planned
/// for an item that is only a queued create: its create is replaced instead.
fn view_target<'v>(list: &'v [std::borrow::Cow<'_, Value>], built: &Built, id: &str) -> Option<&'v Value> {
    let cid = built.marked.get(id).map(|m| m.cipher_id.as_str()).filter(|c| *c != QUEUED)?;
    list.iter().map(AsRef::as_ref).find(|c| id_of(c) == cid)
}

/// `apply` as a queued view sees it: a history question is taken as answered,
/// since the op waits for the real answer when it is sent.
pub(super) fn apply_shown(
    cipher: &Value,
    patch: &Patch,
    keys: &CoreKeys,
) -> Result<core_write::ApplyOutcome, WriteError> {
    let now_ms = i64::try_from(now()).unwrap_or(0).saturating_mul(1000);
    let apply = |p: &Patch| core_write::apply(cipher, p, NS, keys, &WriteRecord::default(), &OsRandom, now_ms);
    match apply(patch) {
        Err(WriteError::Ask(q)) => apply(&Patch { answer: Some((q, HistoryAnswer::WriteToLogin)), ..patch.clone() }),
        other => other,
    }
}

/// Refuses, before it is queued, an op that could never be written.
fn check_queueable(state: &Unlocked, queue: &Queue, op: &Op) -> Result<(), BackendError> {
    match op {
        Op::Create(item) => core_write::new_item(item, NS, &state.core_keys, &OsRandom).map(|_| ()).or_else(queueable),
        Op::Patch(p) => {
            let list = with_queue(&state.sync, queue, &state.core_keys, state.keyring_folder.as_deref(), &state.built);
            let Some(cipher) = view_target(&list, &state.built, &p.id) else { return Ok(()) };
            // Only the sizes are checked here: compare the value against the
            // copy it is applied to.
            let mut trial = p.clone();
            if let (ValueChange::Set { source, base_mark, .. }, CoreScan::Marked(m)) =
                (&mut trial.value, core_scan(cipher, NS, &state.core_keys, &Organizations::None))
            {
                *source = m.source;
                *base_mark = m.mark;
            }
            apply_shown(cipher, &trial, &state.core_keys).map(|_| ()).or_else(queueable)
        }
        Op::Delete { .. } => Ok(()),
    }
}

#[cfg(test)]
#[expect(clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    use std::collections::{BTreeMap, HashMap};

    use dybw_core::sync::enqueue;

    use crate::model::Snapshot;

    fn old() -> MarkedItem {
        MarkedItem {
            cipher_id: "c1".into(),
            revision_date: "2026-01-02T03:04:05Z".into(),
            creation_date: None,
            organization: false,
            source: ValueSource::LoginPassword,
            mark: [9; 32],
            item: ItemData {
                id: "a".into(),
                collection: "login".into(),
                label: "GitHub".into(),
                attributes: BTreeMap::from([
                    ("service".to_owned(), "git".to_owned()),
                    ("bwss:id".to_owned(), "a".to_owned()),
                    ("bwss:name".to_owned(), "GitHub".to_owned()),
                ]),
                secret: Zeroizing::new(b"pw".to_vec()),
                content_type: "text/plain".into(),
                created: 1,
                modified: 2,
                acl: vec!["/usr/bin/git".into()],
            },
        }
    }

    // Ops carry secrets and have no `Debug`: the messages name the kind only.
    fn patch(op: Op) -> Patch {
        let Op::Patch(p) = op else { panic!("expected a patch, got another op") };
        p
    }

    fn sets(p: &Patch) -> Vec<(&str, &str)> {
        p.set.iter().map(|f| (f.name.as_str(), f.value.as_str())).collect()
    }

    fn acl(p: &Patch) -> Vec<&str> {
        p.append_lines.iter().flat_map(|a| a.lines.iter().map(|l| l.as_str())).collect()
    }

    #[test]
    fn plan_put_writes_only_what_changed() {
        let old = old();

        let mut new = old.item.clone();
        new.label = "Renamed".into();
        let p = patch(plan_put(Some(&old), &new));
        assert_eq!((p.id.as_str(), p.base_revision.as_str()), ("a", "2026-01-02T03:04:05Z"));
        assert_eq!(sets(&p), [("bwss:label", "Renamed")]);
        assert!(p.set.iter().all(|f| !f.hidden));
        assert!(p.remove.is_empty() && p.append_lines.is_empty() && p.answer.is_none());
        assert!(matches!(p.value, ValueChange::Keep));

        let mut new = old.item.clone();
        new.secret = Zeroizing::new(b"new".to_vec());
        let p = patch(plan_put(Some(&old), &new));
        assert!(p.set.is_empty() && p.remove.is_empty());
        let (source, secret, base_mark, owned) = value(&p.value);
        assert_eq!((source, secret.as_slice(), base_mark), (CoreSource::LoginPassword, &b"new"[..], [9; 32]));
        assert!(!owned);

        let p = patch(plan_put(Some(&old), &old.item));
        assert!(is_empty(&p));

        let mut new = old.item.clone();
        new.attributes.insert("user".into(), "me".into());
        new.collection = "work".into();
        new.content_type = "application/octet-stream".into();
        new.acl.push("/usr/bin/ssh".into());
        let p = patch(plan_put(Some(&old), &new));
        assert_eq!(p.remove, vec!["bwss:attr:".to_owned()]);
        let mut set = sets(&p);
        set.sort_unstable();
        assert_eq!(
            set,
            [
                ("bwss:attr:service", "git"),
                ("bwss:attr:user", "me"),
                ("bwss:collection", "work"),
                ("bwss:content-type", "application/octet-stream"),
            ]
        );
        // ACL lines are appended to what the server holds, hidden.
        assert_eq!(acl(&p), ["/usr/bin/ssh"]);
        assert_eq!((p.append_lines[0].name.as_str(), p.append_lines[0].hidden), ("bwss:acl", true));

        // Back to the defaults: the fields go away.
        let mut moved = old.clone();
        moved.item.clone_from(&new);
        let mut back = new;
        back.collection = "default".into();
        back.content_type = "text/plain".into();
        let p = patch(plan_put(Some(&moved), &back));
        assert!(p.set.is_empty());
        assert_eq!(p.remove, vec!["bwss:collection".to_owned(), "bwss:content-type".to_owned()]);
    }

    #[test]
    fn plan_put_without_old_creates() {
        let new = old().item;
        let Op::Create(item) = plan_put(None, &new) else { panic!("expected a create") };
        assert_eq!(item.id, "a");
        assert_eq!(item.name, "GitHub");
        assert_eq!(&*item.value, b"pw");
        assert_eq!(item.folder_id, None);
        let shown = crate::backend::ops::item_of(&item);
        assert_eq!((shown.collection.as_str(), shown.label.as_str()), ("login", "GitHub"));
    }

    #[test]
    fn plan_put_never_stores_derived_attributes() {
        let old = old();
        let mut new = old.item.clone();
        new.attributes.insert("bwss:uri".into(), "https://example.org".into());
        new.attributes.insert("bwss:name".into(), "Other".into());
        // Only derived attributes differ: nothing to write.
        let p = patch(plan_put(Some(&old), &new));
        assert!(p.set.is_empty() && p.remove.is_empty());

        new.attributes.insert("user".into(), "me".into());
        let p = patch(plan_put(Some(&old), &new));
        assert!(p.set.iter().all(|f| !f.name.starts_with("bwss:attr:bwss:")), "{:?}", sets(&p));
        assert!(p.set.iter().any(|f| f.name == "bwss:attr:user"));

        let Op::Create(item) = plan_put(None, &new) else { panic!("expected a create") };
        assert!(item.tool_fields.iter().all(|f| !f.name.starts_with("bwss:attr:bwss:")));
    }

    fn field(name: &str, value: &str) -> FieldSet {
        text(name, value)
    }

    fn lines(l: &[&str]) -> Vec<LineAppend> {
        vec![LineAppend {
            name: F_ACL.into(),
            lines: l.iter().map(|s| Zeroizing::new((*s).to_owned())).collect(),
            hidden: true,
        }]
    }

    fn delete(id: &str) -> Op {
        Op::Delete { id: id.into(), base_revision: "r".into(), cipher_id: None, organization_id: None }
    }

    #[test]
    fn queued_patches_of_one_item_merge_on_the_server_base() {
        let first = Patch {
            set: vec![field("bwss:label", "One"), field("bwss:collection", "work")],
            remove: vec!["bwss:content-type".into(), "bwss:collection".into()],
            append_lines: lines(&["/bin/a"]),
            base_revision: "r1".into(),
            cipher_id: Some("c1".into()),
            ..value_patch(set(CoreSource::LoginPassword, b"1", 1))
        };
        let later = Patch {
            set: vec![field("bwss:label", "Two"), field("bwss:attr:k", "v")],
            remove: vec!["bwss:attr:".into(), "bwss:collection".into()],
            append_lines: lines(&["/bin/a", "/bin/b"]),
            base_revision: "r2".into(),
            cipher_id: Some("c1".into()),
            ..value_patch(set(CoreSource::Field, b"2", 2))
        };
        let mut queue = vec![Op::Patch(first), delete("other")];
        // The server still holds what the first change was based on.
        push_op(&mut queue, Op::Patch(later), Some((CoreSource::LoginPassword, [1; 32])));
        assert_eq!(queue.len(), 2);
        let m = patch(queue.remove(0));
        assert_eq!(m.base_revision, "r1");
        // What the first change removes stays, unless the later one says otherwise.
        assert_eq!(
            m.remove,
            vec!["bwss:content-type".to_owned(), "bwss:attr:".to_owned(), "bwss:collection".to_owned()]
        );
        assert_eq!(sets(&m), [("bwss:label", "Two"), ("bwss:attr:k", "v")]);
        assert_eq!(acl(&m), ["/bin/a", "/bin/b"]);
        assert_eq!(value(&m.value), (CoreSource::LoginPassword, b"2".to_vec(), [1; 32], false));

        // Behind a delete of the same item, a patch is not merged.
        let mut queue = vec![delete("a")];
        push_op(&mut queue, Op::Patch(patch(plan_put(Some(&old()), &old().item))), None);
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn undoing_a_push_restores_the_queue_without_a_copy() {
        let mut queue = vec![delete("x"), Op::Patch(value_patch(set(CoreSource::LoginPassword, b"1", 1))), delete("y")];

        // A merge puts the earlier op back as it was, at its place.
        let undo = push_op(&mut queue, Op::Patch(value_patch(set(CoreSource::LoginPassword, b"2", 1))), None);
        assert_eq!(value(&patch(queue[1].clone()).value).1, b"2");
        undo.apply(&mut queue);
        assert_eq!(queue.len(), 3);
        assert_eq!(value(&patch(queue[1].clone()).value).1, b"1");
        assert_eq!(target(&queue[2]), "y");

        // A push is taken off.
        let undo = push_op(&mut queue, delete("z"), None);
        assert_eq!(queue.len(), 4);
        undo.apply(&mut queue);
        assert_eq!(queue.iter().map(target).collect::<Vec<_>>(), ["x", "a", "y"]);

        // So is a delete that cancelled a queued create and what followed it.
        let mut new = old().item;
        new.id = "n".into();
        let mut queue = vec![Op::Create(new_item_of(&new, None)), delete("x")];
        enqueue(&mut queue, NS, Op::Patch(Patch { id: "n".into(), ..value_patch(ValueChange::Keep) }), None);
        let undo = push_op(&mut queue, delete("n"), None);
        assert_eq!(queue.iter().map(target).collect::<Vec<_>>(), ["x"]);
        undo.apply(&mut queue);
        assert_eq!(queue.iter().map(target).collect::<Vec<_>>(), ["n", "x", "n"]);
    }

    fn set(source: CoreSource, secret: &[u8], mark: u8) -> ValueChange {
        ValueChange::Set { source, secret: Zeroizing::new(secret.to_vec()), base_mark: [mark; 32], owned: false }
    }

    fn value(v: &ValueChange) -> (CoreSource, Vec<u8>, [u8; 32], bool) {
        let ValueChange::Set { source, secret, base_mark, owned } = v else { panic!("the value was kept") };
        (*source, secret.to_vec(), *base_mark, *owned)
    }

    fn value_patch(v: ValueChange) -> Patch {
        Patch {
            id: "a".into(),
            cipher_id: None,
            organization_id: None,
            base_revision: "r".into(),
            set: vec![],
            remove: vec![],
            append_lines: vec![],
            value: v,
            answer: None,
        }
    }

    fn merged(first: Patch, later: Patch, server: Option<Base>) -> Patch {
        let mut queue = vec![Op::Patch(first)];
        push_op(&mut queue, Op::Patch(later), server);
        patch(queue.remove(0))
    }

    #[test]
    fn a_change_read_from_the_server_replaces_a_queued_one() {
        // Queued against M0; the server now holds M1 and the app wrote again
        // from it: only the later change is based on what the server holds.
        let first = value_patch(set(CoreSource::LoginPassword, b"one", 0));
        let later = value_patch(set(CoreSource::LoginPassword, b"two", 1));
        let m = merged(first, later, Some((CoreSource::LoginPassword, [1; 32])));
        assert_eq!(value(&m.value), (CoreSource::LoginPassword, b"two".to_vec(), [1; 32], false));
    }

    #[test]
    fn text_after_a_queued_binary_write_goes_to_the_added_field() {
        // The binary write adds bwss:password, which the text was read from.
        let first = value_patch(set(CoreSource::LoginPassword, &[0xff, 0], 0));
        let later = value_patch(set(CoreSource::Field, b"text", 7));
        let m = merged(first, later, Some((CoreSource::LoginPassword, [0; 32])));
        assert_eq!(value(&m.value), (CoreSource::LoginPassword, b"text".to_vec(), [0; 32], true));
        // A text write first: no field was added.
        let first = value_patch(set(CoreSource::LoginPassword, b"t", 0));
        let later = value_patch(set(CoreSource::LoginPassword, b"u", 7));
        let m = merged(first, later, Some((CoreSource::LoginPassword, [0; 32])));
        assert!(!value(&m.value).3);
    }

    #[test]
    fn new_collection_ids_never_read_as_login_or_clash() {
        let taken = |id: &str| ["login", "work"].contains(&id);
        assert_eq!(new_collection_id(" Home ", taken), "home");
        assert_eq!(new_collection_id("Work", taken), "work-2");
        assert_eq!(new_collection_id("Login", taken), "login-2");
        assert_eq!(new_collection_id("default", taken), "default-2");
        assert_eq!(new_collection_id("Session", taken), "session-2");
        assert_eq!(new_collection_id("  ", taken), "collection");
    }

    #[test]
    fn a_later_write_with_nothing_to_set_keeps_the_queued_value() {
        let first = value_patch(set(CoreSource::LoginPassword, b"one", 0));
        let later = value_patch(ValueChange::Keep);
        let m = merged(first, later, Some((CoreSource::LoginPassword, [0; 32])));
        assert_eq!(value(&m.value), (CoreSource::LoginPassword, b"one".to_vec(), [0; 32], false));
    }

    #[test]
    fn a_value_after_a_queued_change_without_one_is_the_value_to_send() {
        let first = value_patch(ValueChange::Keep);
        let later = value_patch(set(CoreSource::Field, b"two", 3));
        // Not the server's base (the first change was never shown), and no
        // earlier value to build on: the later one stands as it is.
        let m = merged(first, later, Some((CoreSource::LoginPassword, [9; 32])));
        assert_eq!(value(&m.value), (CoreSource::Field, b"two".to_vec(), [3; 32], false));
    }

    #[test]
    fn a_patch_queues_behind_a_collection_change_without_merging() {
        let entry = Entry { label: "Work".into(), created: 1, deleted: false };
        let mut queue = Queue { ops: vec![], registry: vec![RegistryOp { collection: "work".into(), entry }] };
        let undo = push_op(&mut queue.ops, Op::Patch(value_patch(set(CoreSource::Field, b"1", 1))), None);
        assert_eq!(queue.len(), 2);
        assert!(matches!(queue.ops[0], Op::Patch(_)) && queue.registry[0].collection == "work");
        undo.apply(&mut queue.ops);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.registry[0].collection, "work");
    }

    #[test]
    fn write_errors_decide_whether_an_op_waits_or_goes() {
        use dybw_core::crypto::CryptoError;
        use dybw_core::vault::Uninspectable;
        assert!(matches!(write_failure(WriteError::SourceChanged, "c"), Failure::Conflict));
        assert!(matches!(write_failure(WriteError::Gone, "c"), Failure::Gone));
        assert!(matches!(write_failure(WriteError::Unmarked, "c"), Failure::Gone));
        let q = HistoryQuestion::EvictsForeign;
        assert!(matches!(write_failure(WriteError::Ask(q), "c"), Failure::Ask(got) if got == q));
        let f = write_failure(WriteError::Uninspectable(Uninspectable::Value), "c3");
        assert!(matches!(&f, Failure::Wait(why) if why == "c3: a value cannot be decrypted"), "{f:?}");
        let f = write_failure(WriteError::Crypto(CryptoError::BadMac), "c9");
        assert!(matches!(&f, Failure::Wait(why) if why == "c9: the item cannot be read"), "{f:?}");
        for e in [WriteError::Unsupported, WriteError::BadClock] {
            let text = format!("c: {e}");
            assert!(matches!(&write_failure(e, "c"), Failure::Wait(why) if *why == text), "{text}");
        }
        for e in [WriteError::TooLong, WriteError::NotesTaken, WriteError::ReadOnly, WriteError::BinaryNotSupported] {
            let text = write_text(&e);
            let f = write_failure(e, "c");
            assert!(matches!(&f, Failure::Permanent { why, cid: None } if *why == text), "{f:?}");
        }
        assert_eq!(write_text(&WriteError::TooLong), "secret is too large for a Bitwarden item");
    }

    #[test]
    fn request_errors_decide_whether_an_op_waits_or_goes() {
        let http = |status| ApiError::Http { status, message: String::new() };
        let mut client = None;
        for e in [http(429), http(503), ApiError::Network("reset".into())] {
            assert!(matches!(api_failure(e, Some("c1"), &mut client), Failure::Transient(_)));
        }
        let f = api_failure(http(400), Some("c1"), &mut client);
        assert!(matches!(&f, Failure::Permanent { why, cid: Some(c) } if why == "HTTP 400" && c == "c1"), "{f:?}");
        for e in [http(401), ApiError::NotLoggedIn, ApiError::NotSynced] {
            assert!(matches!(api_failure(e, None, &mut client), Failure::Transient(_)));
        }
        let mut client = None;
        let f = sync_failure(SyncWriteError::StillChanging, Some("c1"), &mut client);
        assert!(matches!(&f, Failure::Busy(why) if why == "the item keeps changing elsewhere"), "{f:?}");
        assert!(matches!(sync_failure(SyncWriteError::OwnerChanged, None, &mut client), Failure::Wait(_)));
        assert!(matches!(sync_failure(SyncWriteError::MissingId, None, &mut client), Failure::Gone));
        let f = sync_failure(SyncWriteError::Write(WriteError::Gone), Some("c1"), &mut client);
        assert!(matches!(f, Failure::Gone));
    }

    #[test]
    fn an_app_is_told_what_a_failed_live_op_means() {
        let say = refusal;
        let (e, reread) = say(Failure::Locked);
        assert!(matches!(e, BackendError::Locked) && reread.is_none());
        let (e, reread) = say(Failure::Transient("down".into()));
        assert!(matches!(&e, BackendError::Unavailable(m) if m == "down") && reread.is_none(), "{e}");
        let (e, _) = say(Failure::Wait("cannot be read".into()));
        assert!(matches!(&e, BackendError::Unavailable(m) if m == "cannot be read; try again later"), "{e}");
        let (e, _) = say(Failure::Busy("keeps changing".into()));
        assert!(matches!(&e, BackendError::Unavailable(m) if m == "keeps changing; try again"), "{e}");
        let (e, _) = say(Failure::Conflict);
        assert!(matches!(&e, BackendError::Conflict(m) if m == "the secret was changed elsewhere"), "{e}");
        let (e, _) = say(Failure::Gone);
        assert!(matches!(&e, BackendError::Rejected(m) if m == "the item was deleted elsewhere"), "{e}");
        let (e, _) = say(Failure::Ask(HistoryQuestion::FirstWriteBack));
        assert!(matches!(e, BackendError::Ask(HistoryQuestion::FirstWriteBack)), "{e}");
        // A refused write rereads the cipher it was for.
        let (e, reread) = say(Failure::Permanent { why: "HTTP 400".into(), cid: Some("c1".into()) });
        assert!(matches!(&e, BackendError::Rejected(m) if m == "HTTP 400"), "{e}");
        assert_eq!(reread.as_deref(), Some("c1"));
        let (_, reread) = say(Failure::Permanent { why: "HTTP 400".into(), cid: None });
        assert_eq!(reread, None);
    }

    #[test]
    fn only_a_size_problem_refuses_an_op_before_it_is_queued() {
        use dybw_core::crypto::CryptoError;
        use dybw_core::vault::Uninspectable;
        for e in [WriteError::TooLong, WriteError::NotesTaken] {
            let text = write_text(&e);
            let r = queueable(e);
            assert!(matches!(&r, Err(BackendError::Rejected(m)) if *m == text), "{r:?}");
        }
        for e in [
            WriteError::SourceChanged,
            WriteError::Gone,
            WriteError::Unmarked,
            WriteError::Uninspectable(Uninspectable::Value),
            WriteError::Crypto(CryptoError::BadMac),
            WriteError::Ask(HistoryQuestion::FirstWriteBack),
        ] {
            let text = e.to_string();
            let r = queueable(e);
            assert!(matches!(r, Ok(())), "{text}: {r:?}");
        }
    }

    #[test]
    fn status_lists_what_the_user_may_want_to_fix() {
        let built = Built {
            snapshot: Snapshot { collections: vec![], items: vec![], ..Default::default() },
            marked: HashMap::new(),
            registry: Registry::default(),
            registry_ciphers: vec![],
            registry_unreadable: true,
            duplicates: vec![("a".into(), vec!["c2".into(), "c3".into()])],
            skipped: vec![("c4".into(), "c4: item type 3 is not supported".into())],
            ..Built::default()
        };
        assert_eq!(
            status_lines(&built, true),
            [
                "duplicate id a: 2 items ignored".to_owned(),
                "skipped: c4: item type 3 is not supported".to_owned(),
                REGISTRY_UNREADABLE.to_owned(),
            ]
        );
    }

    #[test]
    fn status_lists_items_without_attributes() {
        let bare = |id: &str| {
            let mut m = old();
            m.item.id = id.into();
            m.item.attributes = BTreeMap::from([("bwss:id".to_owned(), id.to_owned())]);
            (id.to_owned(), m)
        };
        let built =
            Built { marked: HashMap::from([bare("zed"), bare("abe"), ("a".into(), old())]), ..Built::default() };
        let says = |derive| status_lines(&built, derive).join("\n");
        assert!(
            says(false).contains("bwss:id only while derived attributes are off")
                && says(false).ends_with(": abe, zed")
        );
        assert!(!says(false).contains("GitHub"), "an item with attributes is not listed");
        assert_eq!(says(true), "", "with derived attributes on they find it");
    }

    #[test]
    fn value_sources_map_to_the_cores() {
        let pairs = [
            (ValueSource::Field, CoreSource::Field),
            (ValueSource::BwssNotes, CoreSource::Notes),
            (ValueSource::NoteBody, CoreSource::NoteBody),
            (ValueSource::LoginPassword, CoreSource::LoginPassword),
        ];
        for (bwss, core) in pairs {
            assert_eq!(core_source(bwss), core);
        }
    }

    #[test]
    fn a_flush_report_says_whether_the_server_may_hold_something_new() {
        use dybw_core::api::ApiError as Api;
        use dybw_core::vault::Uninspectable;
        let waiting = FlushReport {
            kept: vec![("a".into(), "down".into())],
            questions: vec![("b".into(), HistoryQuestion::FirstWriteBack)],
            stuck: vec![("c".into(), Uninspectable::TooLarge)],
            ..FlushReport::default()
        };
        assert!(!log_report(&waiting), "nothing was sent");
        let refused = Api::Http { status: 400, message: String::new() };
        for sent in [
            FlushReport { done: vec!["a".into()], ..FlushReport::default() },
            FlushReport { dropped: vec![("a".into(), WriteError::SourceChanged)], ..FlushReport::default() },
            FlushReport { dropped: vec![("a".into(), WriteError::TooLong)], ..FlushReport::default() },
            FlushReport { refused: vec![("a".into(), refused)], ..FlushReport::default() },
        ] {
            assert!(log_report(&sent));
        }
    }

    #[test]
    fn questions_name_the_item_and_what_an_eviction_loses() {
        let first = question_text("GitHub", HistoryQuestion::FirstWriteBack);
        assert!(first.contains("\"GitHub\"") && first.contains("first change"), "{first}");
        let evict = question_text("GitHub", HistoryQuestion::EvictsForeign);
        assert!(evict.contains("\"GitHub\"") && evict.contains("oldest password in its history"), "{evict}");
        assert!(evict.contains("lost"), "{evict}");
    }
}
