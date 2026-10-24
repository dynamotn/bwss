//! The op runner: every write, live or queued, goes through one path
//! (design §5, §8.3).
//!
//! `run` sends one op. It finds the cipher by `bwss:id`, applies the op (or
//! strips the item, for a delete), and sends it with `lastKnownRevisionDate`.
//! When the server says the copy is out of date, it refetches the cipher and
//! re-applies the op, at most `ATTEMPTS` times in all. What a failure means
//! depends on who waits for the op:
//!
//! * live (an app waits): a transient failure queues the op and the app gets
//!   `Ok`; anything else is an error to the app and nothing is queued;
//! * queued (a flush): a transient failure, or a target that cannot be read
//!   now, keeps the op and stops the flush; a permanent failure drops the op
//!   with a warning and rereads its item from the server.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::BackendError;
use super::bitwarden::{
    BitwardenBackend, Built, KIND_COLLECTIONS, QUEUED, Unlocked, cache_key, ciphers, find_marked, read_registry,
    registry_with_queue, with_queue,
};
use super::ops::Op;
use super::registry::{Entry, REGISTRY_ID, Registry};
use crate::bw::api::ApiError;
use crate::bw::fields::{F_ATTR, F_COLLECTION, F_CONTENT_TYPE, F_LABEL, PREFIX};
use crate::bw::scan::{MarkedItem, Scan, ValueSource, normalize_collection, scan};
use crate::bw::write::{
    Patch, ValueChange, WriteError, apply, has_foreign_content, new_note, new_registry_note, strip,
};
use crate::model::{Attributes, CollectionData, ItemData, LOGIN_COLLECTION, now};

/// Sends per op: the first one and up to two re-applications after an
/// out-of-date rejection.
const ATTEMPTS: usize = 3;
const PLAIN: &str = "text/plain";
const REGISTRY_UNREADABLE: &str =
    "the collection registry cannot be read; collections cannot be changed until it is fixed";

/// The attributes an app set: derived ones (`bwss:*`) are never stored.
pub(crate) fn own_attributes(a: &Attributes) -> Attributes {
    a.iter().filter(|(k, _)| !k.starts_with(PREFIX)).map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// The op that turns `old` (as read) into `new`: only what differs.
pub(crate) fn plan_put(old: Option<&MarkedItem>, new: &ItemData) -> Op {
    let Some(old) = old else {
        let mut item = new.clone();
        item.attributes = own_attributes(&new.attributes);
        item.collection = normalize_collection(&new.collection);
        return Op::Create { id: item.id.clone(), collection: item.collection.clone(), item };
    };
    let mut set = Vec::new();
    let mut remove = Vec::new();
    if new.label != old.item.label {
        set.push((F_LABEL.to_owned(), new.label.clone(), false));
    }
    let attributes = own_attributes(&new.attributes);
    if attributes != own_attributes(&old.item.attributes) {
        // The attribute set is replaced as a whole (§5.3).
        remove.push(F_ATTR.to_owned());
        set.extend(attributes.iter().map(|(k, v)| (format!("{F_ATTR}{k}"), v.clone(), false)));
    }
    let collection = normalize_collection(&new.collection);
    if collection != old.item.collection {
        if collection == LOGIN_COLLECTION {
            remove.push(F_COLLECTION.to_owned());
        } else {
            set.push((F_COLLECTION.to_owned(), collection, false));
        }
    }
    let content_type = if new.content_type.is_empty() { PLAIN } else { new.content_type.as_str() };
    if content_type != old.item.content_type {
        if content_type == PLAIN {
            remove.push(F_CONTENT_TYPE.to_owned());
        } else {
            set.push((F_CONTENT_TYPE.to_owned(), content_type.to_owned(), false));
        }
    }
    let acl_add = new.acl.iter().filter(|l| !old.item.acl.contains(l)).cloned().collect();
    let value = if new.secret == old.item.secret {
        ValueChange::Keep
    } else {
        ValueChange::Set { source: old.source, secret: new.secret.to_vec(), base_mark: old.mark, owned: false }
    };
    let cipher_id = Some(old.cipher_id.clone()).filter(|c| c != QUEUED);
    Op::Patch(Patch {
        id: old.item.id.clone(),
        base_revision: old.revision_date.clone(),
        set,
        remove,
        acl_add,
        value,
        cipher_id,
    })
}

pub(super) fn is_empty(p: &Patch) -> bool {
    p.set.is_empty() && p.remove.is_empty() && p.acl_add.is_empty() && matches!(p.value, ValueChange::Keep)
}

/// The value source and mark of the cached server copy of an item.
pub(super) type Base = (ValueSource, [u8; 32]);

/// One patch with the changes of `first` and then `later`, for the same
/// item. `server` is the cached server copy's base: a later value change
/// read from it (the first one could not be shown, for example because the
/// value changed elsewhere) replaces the first one; a later change read
/// from the first one's result keeps the first one's base, so the value
/// check still compares against what the server holds.
pub(super) fn merge_patches(first: &Patch, mut later: Patch, server: Option<Base>) -> Patch {
    let later_set = std::mem::take(&mut later.set);
    let later_remove = std::mem::take(&mut later.remove);
    let replaces_attributes = later_remove.iter().any(|n| n == F_ATTR);
    let touched = |name: &str| {
        (replaces_attributes && name.starts_with(F_ATTR))
            || later_set.iter().any(|(n, _, _)| n == name)
            || later_remove.iter().any(|n| n == name)
    };
    let mut remove: Vec<String> = first.remove.iter().filter(|n| !touched(n)).cloned().collect();
    let mut set: Vec<(String, String, bool)> = first.set.iter().filter(|(n, _, _)| !touched(n)).cloned().collect();
    remove.extend(later_remove);
    set.extend(later_set);
    let mut acl_add = first.acl_add.clone();
    for line in std::mem::take(&mut later.acl_add) {
        if !acl_add.contains(&line) {
            acl_add.push(line);
        }
    }
    let value = merged_value(&first.value, std::mem::replace(&mut later.value, ValueChange::Keep), server);
    let cipher_id = first.cipher_id.clone().or(later.cipher_id.take());
    Patch { id: first.id.clone(), base_revision: first.base_revision.clone(), set, remove, acl_add, value, cipher_id }
}

fn merged_value(first: &ValueChange, mut later: ValueChange, server: Option<Base>) -> ValueChange {
    let ValueChange::Set { source: later_source, secret, base_mark: later_mark, owned: later_owned } = &mut later
    else {
        return first.clone();
    };
    if server == Some((*later_source, *later_mark)) {
        return later;
    }
    match first {
        ValueChange::Keep => later,
        ValueChange::Set { source, base_mark, secret: first_secret, owned } => {
            // A binary first change to a value the user owns adds
            // `bwss:password` (§5.2): the later change was read from that
            // field and must go there, never into the user's value.
            let added_field = matches!(source, ValueSource::LoginPassword | ValueSource::NoteBody)
                && std::str::from_utf8(first_secret).is_err();
            ValueChange::Set {
                source: *source,
                secret: std::mem::take(secret),
                base_mark: *base_mark,
                owned: *owned || *later_owned || added_field,
            }
        }
    }
}

fn target(op: &Op) -> Option<&str> {
    match op {
        Op::Create { id, .. } | Op::Delete { id, .. } => Some(id),
        Op::Patch(p) => Some(&p.id),
        Op::Registry { .. } => None,
    }
}

/// Queues `op`. A patch for an item whose last queued op is a patch merges
/// into it: two queued patches of one value could not both pass the value
/// check, since the first changes what the second was read from. `server`
/// is the base of the cached server copy of the patched item.
pub(super) fn push_op(queue: &mut Vec<Op>, op: Op, server: Option<Base>) -> Undo {
    let Op::Patch(later) = op else {
        queue.push(op);
        return Undo::Pushed;
    };
    match queue.iter().rposition(|o| target(o) == Some(later.id.as_str())) {
        Some(i) if matches!(queue[i], Op::Patch(_)) => {
            let Op::Patch(first) = &mut queue[i] else { unreachable!("matched a patch") };
            let before = Op::Patch(first.clone());
            *first = merge_patches(first, later, server);
            Undo::Merged(i, Box::new(before))
        }
        _ => {
            queue.push(Op::Patch(later));
            Undo::Pushed
        }
    }
}

/// How to take back a `push_op`, without copying the whole queue.
pub(super) enum Undo {
    /// The op went to the end of the queue.
    Pushed,
    /// The op merged into the one at this index, which held this before.
    Merged(usize, Box<Op>),
}

impl Undo {
    pub(super) fn apply(self, queue: &mut Vec<Op>) {
        match self {
            Self::Pushed => {
                queue.pop();
            }
            Self::Merged(i, before) => queue[i] = *before,
        }
    }
}

/// Extra `bwss status` lines: what the user may want to fix.
pub(super) fn status_lines(built: &Built) -> Vec<String> {
    let mut lines = Vec::new();
    for (id, losers) in &built.duplicates {
        lines.push(format!("duplicate id {id}: {} items ignored", losers.len()));
    }
    // Items an app could not tell apart: one collection, one attribute set.
    // Items without attributes are found by their derived ones instead.
    let mut groups: BTreeMap<(&str, Attributes), Vec<(&str, &str)>> = BTreeMap::new();
    for m in built.marked.values() {
        let attributes = own_attributes(&m.item.attributes);
        if !attributes.is_empty() {
            groups.entry((&m.item.collection, attributes)).or_default().push((&m.item.label, &m.item.id));
        }
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
pub(crate) enum Effect {
    /// Nothing to record: an empty patch, an item already gone or created.
    Nothing,
    /// The server's copy after the write.
    Saved(Value),
    /// The cipher left the vault (moved to the trash).
    Trashed(String),
}

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
    /// Refused for good; `cid` is the cipher to reread.
    Permanent {
        why: String,
        cid: Option<String>,
    },
}

fn write_failure(e: WriteError, cid: &str) -> Failure {
    match e {
        WriteError::Conflict => Failure::Conflict,
        WriteError::Gone | WriteError::Unmarked => Failure::Gone,
        WriteError::Uninspectable(why) => Failure::Wait(why),
        WriteError::Crypto(_) => Failure::Wait(format!("{cid}: the item cannot be read")),
        WriteError::TooLarge | WriteError::NotesTaken => Failure::Permanent { why: e.to_string(), cid: None },
    }
}

fn id_of(cipher: &Value) -> &str {
    cipher.get("id").and_then(Value::as_str).unwrap_or_default()
}

fn live(cipher: &Value) -> bool {
    cipher.get("deletedDate").is_none_or(Value::is_null)
}

/// Where an op's item stands in the cached server copy.
enum Target {
    Found(Value),
    /// It may be there but cannot be read now.
    Held,
    Gone,
}

/// `cipher_id` is the cipher the op was read from, when the op records it.
fn locate(state: &Unlocked, id: &str, cipher_id: Option<&str>) -> Target {
    let list = ciphers(&state.sync);
    if let Some(i) = find_marked(list, id, &state.keys, &state.built.unmarked) {
        return Target::Found(list[i].clone());
    }
    // An item held as last read (§3.4) is still there.
    let held = state
        .built
        .marked
        .get(id)
        .is_some_and(|m| m.cipher_id != QUEUED && list.iter().any(|c| id_of(c) == m.cipher_id && live(c)));
    // After an unlock nothing is held yet: the op's own cipher, or for an op
    // that does not record it any personal cipher, that cannot be read may
    // be the one. Only a target that is surely gone drops the op.
    let maybe = || {
        list.iter().any(|c| {
            cipher_id.is_none_or(|cid| id_of(c) == cid)
                && live(c)
                && c.get("organizationId").is_none_or(Value::is_null)
                && !cache_key(c).is_some_and(|k| state.built.unmarked.contains(&k))
                && matches!(scan(c, &state.keys), Scan::Uninspectable(_))
        })
    };
    if held || maybe() { Target::Held } else { Target::Gone }
}

/// The base of the cached server copy of item `id`, when it can be read.
fn server_base(state: &Unlocked, id: &str) -> Option<Base> {
    let Target::Found(cipher) = locate(state, id, None) else { return None };
    match scan(&cipher, &state.keys) {
        Scan::Marked(m) => Some((m.source, m.mark)),
        _ => None,
    }
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

/// What the next registry write sends.
enum RegistryPlan {
    Create,
    Update(String, Map<String, Value>),
}

impl BitwardenBackend {
    async fn with_state<T>(&self, f: impl FnOnce(&Unlocked) -> Result<T, Failure>) -> Result<T, Failure> {
        let guard = self.state.lock().await;
        f(guard.as_ref().ok_or(Failure::Locked)?)
    }

    async fn api_failure(&self, e: ApiError, cid: Option<&str>) -> Failure {
        match &e {
            _ if e.is_transient() => Failure::Transient(e.to_string()),
            // An expired or revoked session is not the op's fault: log in and
            // sync again before the next write, and keep the op.
            ApiError::Http { status: 401, .. } => {
                self.api.lock().await.logout();
                Failure::Transient(e.to_string())
            }
            _ => Failure::Permanent { why: e.to_string(), cid: cid.map(str::to_owned) },
        }
    }

    /// The server's current copy of `cid`.
    async fn refetch(&self, cid: &str) -> Result<Value, Failure> {
        let fetched = self.api.lock().await.get_item(cid).await;
        match fetched {
            Ok(c) => Ok(c),
            Err(ApiError::Http { status: 404, .. }) => Err(Failure::Gone),
            Err(e) => Err(self.api_failure(e, Some(cid)).await),
        }
    }

    /// The keyring folder's id; it is created on first need (§5.1).
    async fn ensure_keyring_folder(&self) -> Result<String, Failure> {
        let enc = self
            .with_state(|state| Ok(state.keyring_folder.clone().ok_or_else(|| state.keys.user.encrypt_str(&self.root))))
            .await?;
        let enc = match enc {
            Ok(id) => return Ok(id),
            Err(enc) => enc,
        };
        let created = self.api.lock().await.create_folder(&enc).await;
        let folder = match created {
            Ok(f) => f,
            Err(e) => return Err(self.api_failure(e, None).await),
        };
        let id = folder.get("id").and_then(Value::as_str).filter(|id| !id.is_empty()).map(str::to_owned);
        let id = id.ok_or_else(|| Failure::Transient("the server created a folder without an id".into()))?;
        if let Some(s) = self.state.lock().await.as_mut() {
            s.keyring_folder = Some(id.clone());
        }
        Ok(id)
    }

    pub(super) async fn run(&self, op: &Op) -> Result<Effect, Failure> {
        match op {
            Op::Create { item, .. } => self.run_create(item).await,
            Op::Patch(patch) => self.run_patch(patch).await,
            Op::Delete { id, cipher_id, .. } => self.run_delete(id, cipher_id.as_deref()).await,
            Op::Registry { collection, entry } => self.run_registry(collection, entry).await,
        }
    }

    async fn run_create(&self, item: &ItemData) -> Result<Effect, Failure> {
        // Accepted before (for example just before a lock): never twice.
        let exists = self
            .with_state(|s| Ok(find_marked(ciphers(&s.sync), &item.id, &s.keys, &s.built.unmarked).is_some()))
            .await?;
        if exists {
            return Ok(Effect::Nothing);
        }
        let folder = self.ensure_keyring_folder().await?;
        let body =
            self.with_state(|s| new_note(item, Some(&folder), &s.keys).map_err(|e| write_failure(e, ""))).await?;
        let sent = self.api.lock().await.create_item(body).await;
        match sent {
            Ok(reply) => Ok(Effect::Saved(reply)),
            Err(e) => Err(self.api_failure(e, None).await),
        }
    }

    async fn run_patch(&self, patch: &Patch) -> Result<Effect, Failure> {
        if is_empty(patch) {
            return Ok(Effect::Nothing);
        }
        let mut fresh: Option<Value> = None;
        for _ in 0..ATTEMPTS {
            let (cid, body) = self
                .with_state(|state| {
                    let cipher = match fresh.take() {
                        Some(c) => c,
                        None => match locate(state, &patch.id, patch.cipher_id.as_deref()) {
                            Target::Found(c) => c,
                            Target::Held => return Err(Failure::Wait(format!("item {} cannot be read now", patch.id))),
                            Target::Gone => return Err(Failure::Gone),
                        },
                    };
                    let cid = id_of(&cipher).to_owned();
                    let body = apply(&cipher, patch, &state.keys).map_err(|e| write_failure(e, &cid))?;
                    Ok((cid, body))
                })
                .await?;
            let sent = self.api.lock().await.update_item(&cid, body).await;
            match sent {
                Ok(reply) => return Ok(Effect::Saved(reply)),
                // Re-apply bwss's own changes to the fresh copy (§5.6).
                Err(e) if e.is_out_of_date() => fresh = Some(self.refetch(&cid).await?),
                Err(e) => return Err(self.api_failure(e, Some(&cid)).await),
            }
        }
        Err(Failure::Busy("the item keeps changing elsewhere".into()))
    }

    /// Design §5.4: strip, save, then trash only what the server's answer
    /// shows to be bwss's alone.
    async fn run_delete(&self, id: &str, cipher_id: Option<&str>) -> Result<Effect, Failure> {
        let mut fresh: Option<Value> = None;
        for _ in 0..ATTEMPTS {
            let step = self
                .with_state(|state| {
                    let cipher = match fresh.take() {
                        Some(c) => c,
                        None => match locate(state, id, cipher_id) {
                            Target::Found(c) => c,
                            Target::Held => return Err(Failure::Wait(format!("item {id} cannot be read now"))),
                            Target::Gone => return Ok(None),
                        },
                    };
                    match scan(&cipher, &state.keys) {
                        Scan::Marked(m) if m.item.id == id => {}
                        Scan::Uninspectable(why) => return Err(Failure::Wait(why)),
                        // Trashed, unmarked or re-marked elsewhere: it has
                        // already left the keyring.
                        _ => return Ok(None),
                    }
                    let cid = id_of(&cipher).to_owned();
                    match strip(&cipher, &state.keys) {
                        Ok(body) => Ok(Some((cid, body))),
                        Err(WriteError::Gone) => Ok(None),
                        Err(e) => Err(write_failure(e, &cid)),
                    }
                })
                .await?;
            let Some((cid, body)) = step else { return Ok(Effect::Nothing) };
            let sent = self.api.lock().await.update_item(&cid, body).await;
            let reply = match sent {
                Ok(reply) => reply,
                // Start over from the strip, on the fresh copy.
                Err(e) if e.is_out_of_date() => match self.refetch(&cid).await {
                    Ok(c) => {
                        fresh = Some(c);
                        continue;
                    }
                    Err(Failure::Gone) => return Ok(Effect::Nothing),
                    Err(f) => return Err(f),
                },
                Err(e) => return Err(self.api_failure(e, Some(&cid)).await),
            };
            // Decided on what the server returned, never on a stale copy.
            let foreign = self.with_state(|state| Ok(has_foreign_content(&reply, &state.keys))).await?;
            match foreign {
                Ok(false) => {}
                Ok(true) => return Ok(Effect::Saved(reply)),
                Err(e) => {
                    tracing::warn!(cipher = %cid, "the stripped item cannot be inspected ({e}); it is kept");
                    return Ok(Effect::Saved(reply));
                }
            }
            let trashed = self.api.lock().await.trash_item(&cid).await;
            return match trashed {
                Ok(()) => Ok(Effect::Trashed(cid)),
                Err(e) => {
                    tracing::warn!(cipher = %cid, "the item left the keyring but could not be moved to the trash: {e}");
                    Ok(Effect::Saved(reply))
                }
            };
        }
        Err(Failure::Busy("the item keeps changing elsewhere".into()))
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
                    let cid = id_of(&note).to_owned();
                    let (mark, revision, source, mut merged) =
                        match (scan(&note, &state.keys), read_registry(&note, &state.keys)) {
                            (Scan::Marked(m), Ok(Some(r))) if m.item.id == REGISTRY_ID => {
                                (m.mark, m.revision_date, m.source, r)
                            }
                            (Scan::Uninspectable(why), _) => return Err(Failure::Wait(why)),
                            (Scan::Marked(m), Err(_)) if m.item.id == REGISTRY_ID => {
                                return Err(Failure::Wait(REGISTRY_UNREADABLE.into()));
                            }
                            // No longer a registry note: start a new one.
                            _ => return Ok(RegistryPlan::Create),
                        };
                    if !matches!(source, ValueSource::NoteBody | ValueSource::BwssNotes) {
                        return Err(Failure::Wait("the collection registry note has a bwss:password field".into()));
                    }
                    merged.merge(&state.built.registry);
                    // Merged, never put: a newer entry from another device wins.
                    merged.merge(&Registry(BTreeMap::from([(collection.to_owned(), entry.clone())])));
                    let patch = Patch {
                        id: REGISTRY_ID.into(),
                        base_revision: revision,
                        set: Vec::new(),
                        remove: Vec::new(),
                        acl_add: Vec::new(),
                        value: ValueChange::Set {
                            source,
                            secret: merged.to_json().into_bytes(),
                            base_mark: mark,
                            owned: false,
                        },
                        cipher_id: Some(cid.clone()),
                    };
                    let body = apply(&note, &patch, &state.keys).map_err(|e| write_failure(e, &cid))?;
                    Ok(RegistryPlan::Update(cid, body))
                })
                .await?;
            let (cid, body) = match plan {
                RegistryPlan::Update(cid, body) => (cid, body),
                RegistryPlan::Create => return self.create_registry(collection, entry).await,
            };
            let sent = self.api.lock().await.update_item(&cid, body).await;
            match sent {
                Ok(reply) => return Ok(Effect::Saved(reply)),
                Err(e) if e.is_out_of_date() => match self.refetch(&cid).await {
                    Ok(c) => fresh = Some(Some(c)),
                    Err(Failure::Gone) => fresh = Some(None),
                    Err(f) => return Err(f),
                },
                Err(e) => return Err(self.api_failure(e, Some(&cid)).await),
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
                new_registry_note(REGISTRY_ID, KIND_COLLECTIONS, &registry.to_json(), Some(&folder), &state.keys)
                    .map_err(|e| write_failure(e, ""))
            })
            .await?;
        let sent = self.api.lock().await.create_item(body).await;
        match sent {
            Ok(reply) => Ok(Effect::Saved(reply)),
            Err(e) => Err(self.api_failure(e, None).await),
        }
    }

    // --- live ops ------------------------------------------------------------

    /// Clears the in-memory queue once the keyring is locked: it is on disk,
    /// sealed, and its secrets must leave memory with the keys (R12b).
    pub(super) async fn forget_if_locked(&self, queue: &mut Vec<Op>) {
        if self.state.lock().await.is_none() {
            queue.clear();
        }
    }

    /// Runs a live op, or queues it while anything else is queued or the
    /// server cannot be reached.
    async fn submit_locked(&self, queue: &mut Vec<Op>, op: Op) -> Result<(), BackendError> {
        // Keep order: while anything is queued, nothing jumps ahead (§8.3).
        if !queue.is_empty() || !self.can_write().await {
            return self.enqueue(queue, op).await;
        }
        match self.run(&op).await {
            Ok(effect) => self.settle(queue, effect).await,
            Err(Failure::Transient(why)) => {
                tracing::info!("offline ({why}); the change is queued");
                self.enqueue(queue, op).await
            }
            Err(f) => Err(self.refuse(queue, f).await),
        }
    }

    /// The error an app gets for a live op that failed for good.
    async fn refuse(&self, queue: &[Op], f: Failure) -> BackendError {
        match f {
            Failure::Locked => BackendError::Locked,
            Failure::Transient(why) => BackendError::Unavailable(why),
            Failure::Wait(why) => BackendError::Unavailable(format!("{why}; try again later")),
            Failure::Busy(why) => BackendError::Unavailable(format!("{why}; try again")),
            Failure::Conflict => BackendError::Conflict("the secret was changed elsewhere".into()),
            Failure::Gone => BackendError::Rejected("the item was deleted elsewhere".into()),
            Failure::Permanent { why, cid } => {
                tracing::warn!("a change was refused: {why}");
                if let Some(cid) = cid {
                    self.rescan(queue, &cid).await;
                }
                BackendError::Rejected(why)
            }
        }
    }

    async fn settle(&self, queue: &[Op], effect: Effect) -> Result<(), BackendError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        self.absorb(state, queue, effect);
        Ok(())
    }

    /// Rereads `cid` from the server, so the local view returns to the truth.
    async fn rescan(&self, queue: &[Op], cid: &str) {
        let fetched = self.api.lock().await.get_item(cid).await;
        let effect = match fetched {
            Ok(c) => Effect::Saved(c),
            Err(ApiError::Http { status: 404, .. }) => Effect::Trashed(cid.to_owned()),
            Err(e) => {
                tracing::info!(cipher = %cid, "could not reread the item: {e}");
                return;
            }
        };
        if let Err(e) = self.settle(queue, effect).await {
            tracing::debug!("not rescanned: {e}");
        }
    }

    /// Queues `op` behind the others, keeps it on disk and shows it. An op
    /// that could never be written fails here instead of later.
    async fn enqueue(&self, queue: &mut Vec<Op>, op: Op) -> Result<(), BackendError> {
        let mut guard = self.state.lock().await;
        // Locked meanwhile: the op, and its secret, is never kept (R12b).
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        check_queueable(state, queue, &op)?;
        let server = match &op {
            Op::Patch(p) => server_base(state, &p.id),
            _ => None,
        };
        let undo = push_op(queue, op, server);
        // Not on disk, not durable: the app is told, and nothing is kept.
        if let Err(e) = self.save_queue(queue, &state.keys.user) {
            undo.apply(queue);
            return Err(BackendError::Unavailable(format!("the change cannot be queued on disk: {e}")));
        }
        Self::rebuild(state, queue);
        Ok(())
    }

    pub(super) async fn put_locked(&self, queue: &mut Vec<Op>, item: &ItemData) -> Result<(), BackendError> {
        let old = {
            let guard = self.state.lock().await;
            guard.as_ref().ok_or(BackendError::Locked)?.built.marked.get(&item.id).cloned()
        };
        let op = plan_put(old.as_ref(), item);
        if old.as_ref().is_some_and(|m| m.cipher_id == QUEUED) {
            // Not on the server yet: the queued create carries the new version.
            let Op::Create { item: new, .. } = plan_put(None, item) else { unreachable!("no old item gives a create") };
            {
                let guard = self.state.lock().await;
                let state = guard.as_ref().ok_or(BackendError::Locked)?;
                check_queueable(
                    state,
                    queue,
                    &Op::Create { id: new.id.clone(), collection: new.collection.clone(), item: new.clone() },
                )?;
            }
            for op in queue.iter_mut() {
                if let Op::Create { id, collection, item: queued } = op
                    && *id == new.id
                {
                    *collection = new.collection.clone();
                    *queued = new.clone();
                }
            }
            return self.queue_changed(queue).await;
        }
        match op {
            Op::Patch(p) if is_empty(&p) => Ok(()),
            op => self.submit_locked(queue, op).await,
        }
    }

    pub(super) async fn delete_locked(&self, queue: &mut Vec<Op>, id: &str) -> Result<(), BackendError> {
        let target = {
            let guard = self.state.lock().await;
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            state.built.marked.get(id).map(|m| (m.cipher_id.clone(), m.revision_date.clone()))
        };
        let Some((cid, base_revision)) = target else { return Ok(()) };
        if cid == QUEUED {
            // Never reached the server: drop it from the queue.
            queue.retain(|op| target_is_not(op, id));
            return self.queue_changed(queue).await;
        }
        self.submit_locked(queue, Op::Delete { id: id.to_owned(), base_revision, cipher_id: Some(cid) }).await
    }

    pub(super) async fn create_collection_locked(
        &self,
        queue: &mut Vec<Op>,
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
        self.submit_locked(queue, Op::Registry { collection: id.clone(), entry }).await?;
        Ok(CollectionData { id, label: label.to_owned(), created, modified: created })
    }

    /// Applies the delete rule to every item of the collection, then leaves
    /// a tombstone in the registry (§4). `authorized` are the items the
    /// caller authorized: an item that joined the collection since is never
    /// deleted, and the whole delete is refused instead.
    pub(super) async fn delete_collection_locked(
        &self,
        queue: &mut Vec<Op>,
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
            self.submit_locked(queue, Op::Registry { collection: id.to_owned(), entry }).await?;
        }
        Ok(())
    }

    // --- the queue -------------------------------------------------------------

    /// Replays queued writes in order. Stops at the first op that has to
    /// wait.
    pub(super) async fn flush_queue(&self) -> Result<(), BackendError> {
        let mut queue = self.queue.lock().await;
        let result = self.flush_locked(&mut queue).await;
        self.forget_if_locked(&mut queue).await;
        result
    }

    async fn flush_locked(&self, queue: &mut Vec<Op>) -> Result<(), BackendError> {
        if queue.is_empty() || !self.can_write().await {
            return Ok(());
        }
        // queue.json must lose every op the server accepted, even when the
        // keyring locks during the flush (R12c): this copy of the key lives
        // until the flush ends.
        let seal_key = {
            let guard = self.state.lock().await;
            guard.as_ref().ok_or(BackendError::Locked)?.keys.user.clone()
        };
        while let Some(op) = queue.first() {
            let (effect, rescan) = match self.run(op).await {
                Ok(effect) => (effect, None),
                Err(Failure::Locked) => return Err(BackendError::Locked),
                Err(Failure::Transient(why)) => return Err(BackendError::Unavailable(why)),
                Err(Failure::Wait(why) | Failure::Busy(why)) => {
                    tracing::warn!("a queued change waits: {why}");
                    return Err(BackendError::Unavailable(format!("a queued change waits: {why}")));
                }
                Err(Failure::Conflict) => {
                    // Only the value can conflict: keep the label, attribute
                    // and ACL changes merged with it, and send them alone.
                    if let Some(Op::Patch(p)) = queue.first()
                        && !matches!(p.value, ValueChange::Keep)
                    {
                        tracing::warn!(
                            "dropping a queued secret change: the secret was changed elsewhere; \
                             the item's other queued changes are kept"
                        );
                        let rest = Patch { value: ValueChange::Keep, ..p.clone() };
                        queue[0] = Op::Patch(rest);
                        let _ = self.save_queue(queue, &seal_key);
                        continue;
                    }
                    tracing::warn!("dropping a queued change: the secret was changed elsewhere");
                    (Effect::Nothing, None)
                }
                Err(Failure::Gone) => {
                    tracing::warn!("dropping a queued change: its item is gone");
                    (Effect::Nothing, None)
                }
                Err(Failure::Permanent { why, cid }) => {
                    tracing::warn!("dropping a queued change the server refused: {why}");
                    (Effect::Nothing, cid)
                }
            };
            queue.remove(0);
            // Logged in `save_queue`; the server already has the change.
            let _ = self.save_queue(queue, &seal_key);
            self.settle(queue, effect).await?;
            if let Some(cid) = rescan {
                self.rescan(queue, &cid).await;
            }
        }
        Ok(())
    }
}

fn target_is_not(op: &Op, id: &str) -> bool {
    target(op) != Some(id)
}

/// Refuses, before it is queued, an op that could never be written.
fn check_queueable(state: &Unlocked, queue: &[Op], op: &Op) -> Result<(), BackendError> {
    let refused = |e: WriteError| match e {
        WriteError::TooLarge | WriteError::NotesTaken => Err(BackendError::Rejected(e.to_string())),
        // Everything else is decided against the server when the op runs.
        _ => Ok(()),
    };
    match op {
        Op::Create { item, .. } => new_note(item, None, &state.keys).map(|_| ()).or_else(refused),
        Op::Patch(p) => {
            let list =
                with_queue(&state.sync, queue, &state.keys, state.keyring_folder.as_deref(), &state.built.unmarked);
            let Some(i) = find_marked(&list, &p.id, &state.keys, &state.built.unmarked) else { return Ok(()) };
            // Only the sizes are checked here: compare the value against the
            // copy it is applied to.
            let mut trial = p.clone();
            if let (ValueChange::Set { source, base_mark, .. }, Scan::Marked(m)) =
                (&mut trial.value, scan(&list[i], &state.keys))
            {
                *source = m.source;
                *base_mark = m.mark;
            }
            apply(&list[i], &trial, &state.keys).map(|_| ()).or_else(refused)
        }
        Op::Delete { .. } | Op::Registry { .. } => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use zeroize::Zeroizing;

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

    fn patch(op: Op) -> Patch {
        match op {
            Op::Patch(p) => p,
            _ => panic!("expected a patch"),
        }
    }

    #[test]
    fn plan_put_writes_only_what_changed() {
        let old = old();

        let mut new = old.item.clone();
        new.label = "Renamed".into();
        let p = patch(plan_put(Some(&old), &new));
        assert_eq!((p.id.as_str(), p.base_revision.as_str()), ("a", "2026-01-02T03:04:05Z"));
        assert_eq!(p.set, vec![("bwss:label".to_owned(), "Renamed".to_owned(), false)]);
        assert!(p.remove.is_empty() && p.acl_add.is_empty());
        assert!(matches!(p.value, ValueChange::Keep));

        let mut new = old.item.clone();
        new.secret = Zeroizing::new(b"new".to_vec());
        let p = patch(plan_put(Some(&old), &new));
        assert!(p.set.is_empty() && p.remove.is_empty());
        match &p.value {
            ValueChange::Set { source, secret, base_mark, owned } => {
                assert_eq!(
                    (*source, secret.as_slice(), *base_mark),
                    (ValueSource::LoginPassword, &b"new"[..], [9; 32])
                );
                assert!(!owned);
            }
            ValueChange::Keep => panic!("the secret changed"),
        }

        let p = patch(plan_put(Some(&old), &old.item));
        assert!(is_empty(&p));

        let mut new = old.item.clone();
        new.attributes.insert("user".into(), "me".into());
        new.collection = "work".into();
        new.content_type = "application/octet-stream".into();
        new.acl.push("/usr/bin/ssh".into());
        let p = patch(plan_put(Some(&old), &new));
        assert_eq!(p.remove, vec!["bwss:attr:".to_owned()]);
        let mut set: Vec<_> = p.set.iter().map(|(n, v, _)| (n.as_str(), v.as_str())).collect();
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
        assert_eq!(p.acl_add, vec!["/usr/bin/ssh".to_owned()]);

        // Back to the defaults: the fields go away.
        let mut moved = old.clone();
        moved.item = new.clone();
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
        match plan_put(None, &new) {
            Op::Create { id, collection, item } => {
                assert_eq!((id.as_str(), collection.as_str()), ("a", "login"));
                assert_eq!(item.label, "GitHub");
                assert_eq!(&*item.secret, b"pw");
            }
            _ => panic!("expected a create"),
        }
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
        assert!(p.set.iter().all(|(n, _, _)| !n.starts_with("bwss:attr:bwss:")), "{:?}", p.set);
        assert!(p.set.iter().any(|(n, _, _)| n == "bwss:attr:user"));

        match plan_put(None, &new) {
            Op::Create { item, .. } => assert!(item.attributes.keys().all(|k| !k.starts_with("bwss:"))),
            _ => panic!("expected a create"),
        }
    }

    #[test]
    fn queued_patches_of_one_item_merge_on_the_server_base() {
        let first = Patch {
            id: "a".into(),
            base_revision: "r1".into(),
            set: vec![("bwss:label".into(), "One".into(), false), ("bwss:collection".into(), "work".into(), false)],
            remove: vec![],
            acl_add: vec!["/bin/a".into()],
            value: set(ValueSource::LoginPassword, b"1", 1),
            cipher_id: Some("c1".into()),
        };
        let later = Patch {
            id: "a".into(),
            base_revision: "r2".into(),
            set: vec![("bwss:label".into(), "Two".into(), false), ("bwss:attr:k".into(), "v".into(), false)],
            remove: vec!["bwss:attr:".into(), "bwss:collection".into()],
            acl_add: vec!["/bin/a".into(), "/bin/b".into()],
            value: set(ValueSource::Field, b"2", 2),
            cipher_id: Some("c1".into()),
        };
        let mut queue =
            vec![Op::Patch(first), Op::Delete { id: "other".into(), base_revision: "r".into(), cipher_id: None }];
        // The server still holds what the first change was based on.
        push_op(&mut queue, Op::Patch(later), Some((ValueSource::LoginPassword, [1; 32])));
        assert_eq!(queue.len(), 2);
        let m = patch(queue.remove(0));
        assert_eq!(m.base_revision, "r1");
        assert_eq!(m.remove, vec!["bwss:attr:".to_owned(), "bwss:collection".to_owned()]);
        assert_eq!(
            m.set,
            vec![("bwss:label".to_owned(), "Two".to_owned(), false), ("bwss:attr:k".to_owned(), "v".to_owned(), false)]
        );
        assert_eq!(m.acl_add, vec!["/bin/a".to_owned(), "/bin/b".to_owned()]);
        assert_eq!(value(&m.value), (ValueSource::LoginPassword, b"2".to_vec(), [1; 32], false));

        // Behind a delete of the same item, a patch is not merged.
        let mut queue = vec![Op::Delete { id: "a".into(), base_revision: "r".into(), cipher_id: None }];
        push_op(&mut queue, Op::Patch(patch(plan_put(Some(&old()), &old().item))), None);
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn undoing_a_push_restores_the_queue_without_a_copy() {
        let mut queue = vec![Op::Patch(value_patch(set(ValueSource::LoginPassword, b"1", 1)))];

        // A merge puts the earlier op back as it was.
        let undo = push_op(&mut queue, Op::Patch(value_patch(set(ValueSource::LoginPassword, b"2", 1))), None);
        assert_eq!(value(&patch(queue[0].clone()).value).1, b"2");
        undo.apply(&mut queue);
        assert_eq!(queue.len(), 1);
        assert_eq!(value(&patch(queue[0].clone()).value).1, b"1");

        // A push is popped.
        let undo = push_op(&mut queue, Op::Delete { id: "z".into(), base_revision: "r".into(), cipher_id: None }, None);
        assert_eq!(queue.len(), 2);
        undo.apply(&mut queue);
        assert_eq!(queue.len(), 1);
    }

    fn set(source: ValueSource, secret: &[u8], mark: u8) -> ValueChange {
        ValueChange::Set { source, secret: secret.to_vec(), base_mark: [mark; 32], owned: false }
    }

    fn value(v: &ValueChange) -> (ValueSource, Vec<u8>, [u8; 32], bool) {
        match v {
            ValueChange::Set { source, secret, base_mark, owned } => (*source, secret.clone(), *base_mark, *owned),
            ValueChange::Keep => panic!("the value was set"),
        }
    }

    fn value_patch(v: ValueChange) -> Patch {
        Patch {
            id: "a".into(),
            base_revision: "r".into(),
            set: vec![],
            remove: vec![],
            acl_add: vec![],
            value: v,
            cipher_id: None,
        }
    }

    #[test]
    fn a_change_read_from_the_server_replaces_a_queued_one() {
        // Queued against M0; the server now holds M1 and the app wrote again
        // from it: only the later change is based on what the server holds.
        let first = value_patch(set(ValueSource::LoginPassword, b"one", 0));
        let later = value_patch(set(ValueSource::LoginPassword, b"two", 1));
        let m = merge_patches(&first, later, Some((ValueSource::LoginPassword, [1; 32])));
        assert_eq!(value(&m.value), (ValueSource::LoginPassword, b"two".to_vec(), [1; 32], false));
    }

    #[test]
    fn text_after_a_queued_binary_write_goes_to_the_added_field() {
        // The binary write adds bwss:password, which the text was read from.
        let first = value_patch(set(ValueSource::LoginPassword, &[0xff, 0], 0));
        let later = value_patch(set(ValueSource::Field, b"text", 7));
        let m = merge_patches(&first, later, Some((ValueSource::LoginPassword, [0; 32])));
        assert_eq!(value(&m.value), (ValueSource::LoginPassword, b"text".to_vec(), [0; 32], true));
        // A text write first: no field was added.
        let first = value_patch(set(ValueSource::LoginPassword, b"t", 0));
        let later = value_patch(set(ValueSource::LoginPassword, b"u", 7));
        let m = merge_patches(&first, later, Some((ValueSource::LoginPassword, [0; 32])));
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
}
