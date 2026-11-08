//! Queued writes and versioned state files.
//!
//! Queued ops hold secrets, ids and labels, so the whole list is sealed with
//! the queue key (design §8.1, stricter: op kinds are hidden too). State
//! files carry `"format": 2` (the queue: 3); anything older is set aside,
//! never overwritten.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use dybw_core::crypto::{CryptoError, SymmetricKey};
use dybw_core::ports::Random;
use dybw_core::sync::Op as CoreOp;
use dybw_core::vault::ValueSource;
use dybw_core::vault::write::{FieldSet, HistoryAnswer, HistoryQuestion, LineAppend, NewItem, Patch, ValueChange};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::bw::fields::{F_ACL, F_ATTR, F_COLLECTION, F_CONTENT_TYPE, F_CREATED, F_LABEL, PREFIX};
use crate::bw::scan::normalize_collection;
use crate::model::{ItemData, LOGIN_COLLECTION};

use super::registry::Entry;

pub(crate) const FORMAT: u64 = 2;
/// `queue.json` sealed with the queue key. Format 2 was sealed with the user
/// key itself and is opened only during the one-time migration.
pub(crate) const QUEUE_FORMAT: u64 = 3;
const PLAIN: &str = "text/plain";

/// A queued change to the collection registry: bwss's own op (design §4).
#[derive(Clone)]
pub struct RegistryOp {
    pub collection: String,
    pub entry: Entry,
}

/// The queued writes: the item ops as the core queues them, then the
/// collection registry changes, each list in order (design §8.3).
#[derive(Clone, Default)]
pub struct Queue {
    pub ops: Vec<CoreOp>,
    pub registry: Vec<RegistryOp>,
}

impl Queue {
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty() && self.registry.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ops.len() + self.registry.len()
    }

    /// Drops every op, and with them their secrets.
    pub fn clear(&mut self) {
        self.ops.clear();
        self.registry.clear();
    }
}

/// The `bwss:id` an item op is for.
pub fn target(op: &CoreOp) -> &str {
    match op {
        CoreOp::Create(item) => &item.id,
        CoreOp::Patch(p) => &p.id,
        CoreOp::Delete { id, .. } => id,
    }
}

/// The core's new item for `item`: the fields bwss always wrote, in the same
/// order (design §5.1), named by its label.
pub fn new_item_of(item: &ItemData, folder_id: Option<&str>) -> NewItem {
    let field =
        |name: String, value: &str, hidden: bool| FieldSet { name, value: Zeroizing::new(value.to_owned()), hidden };
    // Derived attributes (and anything else in bwss's namespace) are never stored as attributes.
    let mut tool_fields: Vec<FieldSet> = item
        .attributes
        .iter()
        .filter(|(n, _)| !n.starts_with(PREFIX))
        .map(|(n, v)| field(format!("{F_ATTR}{n}"), v, false))
        .collect();
    if normalize_collection(&item.collection) != LOGIN_COLLECTION {
        tool_fields.push(field(F_COLLECTION.into(), &item.collection, false));
    }
    // ADR 0015: a label is read from `bwss:label`, else it is the id.
    if !item.label.is_empty() && item.label != item.id {
        tool_fields.push(field(F_LABEL.into(), &item.label, false));
    }
    if item.content_type != PLAIN {
        tool_fields.push(field(F_CONTENT_TYPE.into(), &item.content_type, false));
    }
    if !item.acl.is_empty() {
        tool_fields.push(field(F_ACL.into(), &item.acl.join("\n"), true));
    }
    tool_fields.push(field(F_CREATED.into(), &item.created.to_string(), false));
    NewItem {
        id: item.id.clone(),
        value: item.secret.clone(),
        name: item.label.clone(),
        folder_id: folder_id.map(str::to_owned),
        tool_fields,
    }
}

/// The item a new item holds: `new_item_of` read back.
pub fn item_of(new: &NewItem) -> ItemData {
    let get = |name: &str| new.tool_fields.iter().find(|f| f.name == name).map(|f| f.value.as_str());
    let created = get(F_CREATED).and_then(|c| c.trim().parse().ok()).unwrap_or(0);
    let lines = |a: &str| a.lines().filter(|l| !l.trim().is_empty()).map(str::to_owned).collect();
    ItemData {
        id: new.id.clone(),
        collection: get(F_COLLECTION).map_or_else(|| LOGIN_COLLECTION.to_owned(), normalize_collection),
        label: get(F_LABEL).filter(|l| !l.is_empty()).unwrap_or(&new.id).to_owned(),
        attributes: new
            .tool_fields
            .iter()
            .filter_map(|f| f.name.strip_prefix(F_ATTR).map(|n| (n.to_owned(), f.value.as_str().to_owned())))
            .collect(),
        secret: new.value.clone(),
        content_type: get(F_CONTENT_TYPE).unwrap_or(PLAIN).to_owned(),
        created,
        modified: created,
        acl: get(F_ACL).map(lines).unwrap_or_default(),
    }
}

// shortcut: the file keeps format 3, read and written through these mirrors of bwss's old ops; B6 moves it to
// format 4 (core ops, registry ops and write records in one sealed set).

/// Serde mirror of `ItemData`, which deliberately has no serde of its own.
#[derive(Serialize, Deserialize)]
struct SealedItem {
    id: String,
    collection: String,
    label: String,
    attributes: BTreeMap<String, String>,
    secret: Zeroizing<Vec<u8>>,
    content_type: String,
    created: u64,
    modified: u64,
    acl: Vec<String>,
}

impl From<ItemData> for SealedItem {
    fn from(i: ItemData) -> Self {
        Self {
            id: i.id,
            collection: i.collection,
            label: i.label,
            attributes: i.attributes,
            secret: i.secret,
            content_type: i.content_type,
            created: i.created,
            modified: i.modified,
            acl: i.acl,
        }
    }
}

impl From<SealedItem> for ItemData {
    fn from(i: SealedItem) -> Self {
        Self {
            id: i.id,
            collection: i.collection,
            label: i.label,
            attributes: i.attributes,
            secret: i.secret,
            content_type: i.content_type,
            created: i.created,
            modified: i.modified,
            acl: i.acl,
        }
    }
}

/// The value sources by bwss's old names.
#[derive(Clone, Copy, Serialize, Deserialize)]
enum SealedSource {
    Field,
    BwssNotes,
    NoteBody,
    LoginPassword,
}

impl From<ValueSource> for SealedSource {
    fn from(s: ValueSource) -> Self {
        match s {
            ValueSource::Field => Self::Field,
            ValueSource::Notes => Self::BwssNotes,
            ValueSource::NoteBody => Self::NoteBody,
            ValueSource::LoginPassword => Self::LoginPassword,
        }
    }
}

impl From<SealedSource> for ValueSource {
    fn from(s: SealedSource) -> Self {
        match s {
            SealedSource::Field => Self::Field,
            SealedSource::BwssNotes => Self::Notes,
            SealedSource::NoteBody => Self::NoteBody,
            SealedSource::LoginPassword => Self::LoginPassword,
        }
    }
}

#[derive(Serialize, Deserialize)]
enum SealedValue {
    Keep,
    Set {
        source: SealedSource,
        secret: Zeroizing<Vec<u8>>,
        base_mark: [u8; 32],
        #[serde(default)]
        owned: bool,
    },
}

#[derive(Serialize, Deserialize)]
struct SealedPatch {
    id: String,
    base_revision: String,
    /// `(field, plaintext value, hidden)`.
    set: Vec<(String, Zeroizing<String>, bool)>,
    remove: Vec<String>,
    /// The lines added to `bwss:acl`.
    acl_add: Vec<Zeroizing<String>>,
    value: SealedValue,
    #[serde(default)]
    cipher_id: Option<String>,
    /// The user's answer to a history question (ADR 0016).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    answer: Option<(HistoryQuestion, HistoryAnswer)>,
}

impl From<SealedPatch> for Patch {
    fn from(p: SealedPatch) -> Self {
        let append_lines = if p.acl_add.is_empty() {
            Vec::new()
        } else {
            vec![LineAppend { name: F_ACL.into(), lines: p.acl_add, hidden: true }]
        };
        Patch {
            id: p.id,
            cipher_id: p.cipher_id,
            organization_id: None,
            base_revision: p.base_revision,
            set: p.set.into_iter().map(|(name, value, hidden)| FieldSet { name, value, hidden }).collect(),
            remove: p.remove,
            append_lines,
            value: match p.value {
                SealedValue::Keep => ValueChange::Keep,
                SealedValue::Set { source, secret, base_mark, owned } => {
                    ValueChange::Set { source: source.into(), secret, base_mark, owned }
                }
            },
            answer: p.answer,
        }
    }
}

impl From<Patch> for SealedPatch {
    fn from(p: Patch) -> Self {
        // bwss appends to `bwss:acl` only.
        let acl_add = p.append_lines.into_iter().filter(|a| a.name == F_ACL).flat_map(|a| a.lines).collect();
        SealedPatch {
            id: p.id,
            base_revision: p.base_revision,
            set: p.set.into_iter().map(|f| (f.name, f.value, f.hidden)).collect(),
            remove: p.remove,
            acl_add,
            value: match p.value {
                ValueChange::Keep => SealedValue::Keep,
                ValueChange::Set { source, secret, base_mark, owned } => {
                    SealedValue::Set { source: source.into(), secret, base_mark, owned }
                }
            },
            cipher_id: p.cipher_id,
            answer: p.answer,
        }
    }
}

#[derive(Serialize, Deserialize)]
enum SealedOp {
    Create {
        id: String,
        collection: String,
        item: SealedItem,
    },
    Patch(SealedPatch),
    Delete {
        id: String,
        base_revision: String,
        /// Absent in queues written before it was recorded.
        #[serde(default)]
        cipher_id: Option<String>,
    },
    Registry {
        collection: String,
        entry: Entry,
    },
}

fn sealed(op: &CoreOp) -> SealedOp {
    match op {
        CoreOp::Create(new) => {
            let item = item_of(new);
            SealedOp::Create { id: item.id.clone(), collection: item.collection.clone(), item: item.into() }
        }
        CoreOp::Patch(p) => SealedOp::Patch(p.clone().into()),
        CoreOp::Delete { id, base_revision, cipher_id, .. } => {
            SealedOp::Delete { id: id.clone(), base_revision: base_revision.clone(), cipher_id: cipher_id.clone() }
        }
    }
}

/// Seals the whole queue as one EncString under `"ops"`; only `"format"`
/// stays plain.
///
/// Known limitation: while `serde_json` serializes (here) and parses (in
/// `unseal`), its `Vec<u8>` growth can leave partial unwiped copies of the
/// queued secrets behind.
pub fn seal(queue: &Queue, key: &SymmetricKey, rng: &impl Random) -> Result<Value, CryptoError> {
    let mut mirror: Vec<SealedOp> = queue.ops.iter().map(sealed).collect();
    mirror.extend(
        queue.registry.iter().map(|r| SealedOp::Registry { collection: r.collection.clone(), entry: r.entry.clone() }),
    );
    // Plain derived-Serialize structs always serialize.
    let json = Zeroizing::new(serde_json::to_vec(&mirror).map_err(|_| CryptoError::Malformed)?);
    Ok(serde_json::json!({ "format": QUEUE_FORMAT, "ops": key.encrypt(&json, rng)? }))
}

/// Opens a sealed queue. A wrong key or tampered data is an error; the
/// caller decides what to do with the file.
/// Which key may open which format is the caller's decision.
pub fn unseal(file: &Value, key: &SymmetricKey) -> Result<Queue, CryptoError> {
    if !matches!(file.get("format").and_then(Value::as_u64), Some(FORMAT | QUEUE_FORMAT)) {
        return Err(CryptoError::Malformed);
    }
    let enc = file.get("ops").and_then(Value::as_str).ok_or(CryptoError::Malformed)?;
    let plain = key.decrypt(enc)?;
    let mirror: Vec<SealedOp> = serde_json::from_slice(&plain).map_err(|_| CryptoError::Malformed)?;
    let mut queue = Queue::default();
    for op in mirror {
        match op {
            // The folder is found, or made, when the create is sent.
            SealedOp::Create { item, .. } => queue.ops.push(CoreOp::Create(new_item_of(&item.into(), None))),
            SealedOp::Patch(p) => queue.ops.push(CoreOp::Patch(p.into())),
            SealedOp::Delete { id, base_revision, cipher_id } => {
                queue.ops.push(CoreOp::Delete { id, base_revision, cipher_id, organization_id: None });
            }
            SealedOp::Registry { collection, entry } => queue.registry.push(RegistryOp { collection, entry }),
        }
    }
    Ok(queue)
}

/// Result of reading a state file.
///
/// On `Unreadable` the file is still in place and may hold data (for example
/// queued writes): callers must not overwrite or delete it.
#[derive(Debug)]
pub enum Loaded<T> {
    /// The file could not be read or set aside.
    Unreadable(std::io::Error),
    Ok(T),
    Missing,
    SetAside(PathBuf),
}

/// Reads a state file. A file that is not JSON, or lacks `"format": 2`, is
/// renamed aside (never overwriting an earlier set-aside) and reported.
pub fn read_versioned(path: &Path, legacy_suffix: &str) -> Loaded<Value> {
    read_formats(path, legacy_suffix, &[FORMAT])
}

/// `read_versioned` for a file that may carry any of `formats`.
pub fn read_formats(path: &Path, legacy_suffix: &str, formats: &[u64]) -> Loaded<Value> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Loaded::Missing,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "cannot read state file");
            return Loaded::Unreadable(e);
        }
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(v) if v.get("format").and_then(Value::as_u64).is_some_and(|f| formats.contains(&f)) => Loaded::Ok(v),
        Ok(_) => set_aside(path, legacy_suffix),
        Err(_) => set_aside(path, "corrupt"),
    }
}

/// Renames `path` to `<name>.<suffix>` (numbered, never overwriting).
pub(crate) fn set_aside(path: &Path, suffix: &str) -> Loaded<Value> {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut target = path.with_file_name(format!("{name}.{suffix}"));
    let mut n = 0u32;
    while target.exists() {
        n += 1;
        target = path.with_file_name(format!("{name}.{suffix}.{n}"));
    }
    match std::fs::rename(path, &target) {
        Ok(()) => {
            tracing::warn!(path = %path.display(), moved_to = %target.display(), "set aside unreadable state file");
            Loaded::SetAside(target)
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "cannot set aside state file");
            Loaded::Unreadable(e)
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::core_ports::random::OsRandom;

    fn item() -> ItemData {
        ItemData {
            id: "id-7f3a-unique".into(),
            collection: "work".into(),
            label: "label-xyzzy-unique".into(),
            attributes: BTreeMap::from([("k".to_string(), "v".to_string())]),
            secret: Zeroizing::new(b"s3cr3t-plumb-unique".to_vec()),
            content_type: "text/plain".into(),
            created: 1,
            modified: 1,
            acl: vec!["/usr/bin/x".into()],
        }
    }

    fn key() -> SymmetricKey {
        SymmetricKey::generate(&OsRandom).unwrap()
    }

    fn seal(queue: &Queue, key: &SymmetricKey) -> Value {
        super::seal(queue, key, &OsRandom).unwrap()
    }

    fn delete(id: &str, cipher_id: Option<&str>) -> CoreOp {
        CoreOp::Delete {
            id: id.into(),
            base_revision: "rev".into(),
            cipher_id: cipher_id.map(str::to_owned),
            organization_id: None,
        }
    }

    /// Compiles only while queued secrets are wiped on drop.
    fn _assert_zeroizing(s: &SealedItem) -> &Zeroizing<Vec<u8>> {
        &s.secret
    }

    #[test]
    fn sealed_item_secret_is_zeroizing() {
        let sealed = SealedItem::from(item());
        assert_eq!(_assert_zeroizing(&sealed).as_slice(), b"s3cr3t-plumb-unique");
        let back = ItemData::from(sealed);
        assert_eq!(back, item());
    }

    #[test]
    fn sealed_queue_round_trips_and_hides_secrets() {
        let key = key();
        let queue = Queue {
            ops: vec![CoreOp::Create(new_item_of(&item(), Some("f1"))), delete("id-7f3a-unique", Some("c9"))],
            registry: vec![RegistryOp {
                collection: "c".into(),
                entry: Entry { label: "label-xyzzy-unique".into(), created: 3, deleted: false },
            }],
        };
        let sealed = seal(&queue, &key);
        assert_eq!(sealed["format"], 3);
        let text = sealed.to_string();
        for needle in ["s3cr3t-plumb-unique", "id-7f3a-unique", "label-xyzzy-unique"] {
            assert!(!text.contains(needle), "{needle} leaked");
        }
        let back = unseal(&sealed, &key).unwrap();
        assert_eq!((back.ops.len(), back.registry.len()), (2, 1));
        let CoreOp::Create(got) = &back.ops[0] else { panic!("expected Create") };
        assert_eq!(item_of(got), item());
        assert_eq!(got.folder_id, None, "the folder is looked up when the create is sent");
        assert!(matches!(&back.ops[1], CoreOp::Delete { base_revision, cipher_id, .. }
            if base_revision == "rev" && cipher_id.as_deref() == Some("c9")));
        assert_eq!(back.registry[0].entry.created, 3);
        assert!(unseal(&sealed, &super::tests::key()).is_err());
        assert!(matches!(unseal(&serde_json::json!({"ops": "x"}), &key), Err(CryptoError::Malformed)));
    }

    #[test]
    fn a_new_item_keeps_the_fields_bwss_always_wrote() {
        let new = new_item_of(&item(), Some("f1"));
        let names: Vec<&str> = new.tool_fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["bwss:attr:k", "bwss:collection", "bwss:label", "bwss:acl", "bwss:created"]);
        assert!(new.tool_fields.iter().all(|f| f.hidden == (f.name == "bwss:acl")));
        assert_eq!((new.name.as_str(), new.folder_id.as_deref()), ("label-xyzzy-unique", Some("f1")));
        // Defaults are not written, and neither is a derived attribute.
        let mut plain = item();
        plain.collection = "default".into();
        plain.label = plain.id.clone();
        plain.acl.clear();
        plain.content_type = "application/x".into();
        plain.attributes.insert("bwss:name".into(), "n".into());
        let new = new_item_of(&plain, None);
        let names: Vec<&str> = new.tool_fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["bwss:attr:k", "bwss:content-type", "bwss:created"]);
        let back = item_of(&new);
        assert_eq!((back.collection.as_str(), back.label.as_str()), ("login", "id-7f3a-unique"));
        assert_eq!(back.content_type, "application/x");
    }

    #[test]
    fn legacy_queue_is_renamed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("queue.json");
        std::fs::write(&p, r#"{"ops":[]}"#).unwrap();
        let got = read_versioned(&p, "legacy");
        let Loaded::SetAside(to) = &got else { panic!("expected SetAside, got {got:?}") };
        assert_eq!(*to, dir.path().join("queue.json.legacy"));
        assert!(!p.exists());
        assert!(dir.path().join("queue.json.legacy").exists());
    }

    #[test]
    fn corrupt_queue_is_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("queue.json");
        std::fs::write(&p, r#"{"op":"#).unwrap();
        assert!(matches!(read_versioned(&p, "legacy"), Loaded::SetAside(_)));
        assert!(dir.path().join("queue.json.corrupt").exists());
        // A second corrupt file does not overwrite the first.
        std::fs::write(&p, "nope").unwrap();
        let got = read_versioned(&p, "legacy");
        let Loaded::SetAside(to) = &got else { panic!("expected SetAside, got {got:?}") };
        assert_eq!(*to, dir.path().join("queue.json.corrupt.1"));
    }

    #[test]
    fn current_format_loads_and_missing_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("queue.json");
        assert!(matches!(read_versioned(&p, "legacy"), Loaded::Missing));
        std::fs::write(&p, r#"{"format":2,"ops":"x"}"#).unwrap();
        assert!(matches!(read_versioned(&p, "legacy"), Loaded::Ok(v) if v["format"] == 2));
    }

    #[test]
    fn unreadable_file_is_reported_not_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("queue.json");
        std::fs::create_dir(&p).unwrap();
        assert!(matches!(read_versioned(&p, "legacy"), Loaded::Unreadable(_)));
        assert!(p.exists());
    }

    #[test]
    fn failed_set_aside_is_reported_not_missing() {
        // The rename fails whoever runs the test: there is nothing to move.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("queue.json");
        let got = set_aside(&p, "legacy");
        let Loaded::Unreadable(e) = &got else { panic!("expected Unreadable, got {got:?}") };
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        assert!(!dir.path().join("queue.json.legacy").exists());
    }

    #[test]
    fn a_corrupt_file_that_cannot_be_set_aside_is_unreadable_and_kept() {
        // `<name>.corrupt` exceeds NAME_MAX, so the rename fails for any user.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("q".repeat(250));
        std::fs::write(&p, "nope").unwrap();
        let got = read_versioned(&p, "legacy");
        let Loaded::Unreadable(e) = &got else { panic!("expected Unreadable, got {got:?}") };
        assert_ne!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "nope", "the file stays where it was");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn patch_round_trips() {
        let key = key();
        let patch = Patch {
            id: "pid".into(),
            cipher_id: Some("c1".into()),
            organization_id: None,
            base_revision: "r1".into(),
            set: vec![FieldSet { name: "bwss:label".into(), value: Zeroizing::new("l".into()), hidden: false }],
            remove: vec!["bwss:attr:".into()],
            append_lines: vec![LineAppend {
                name: "bwss:acl".into(),
                lines: vec![Zeroizing::new("/bin/a".into())],
                hidden: true,
            }],
            value: ValueChange::Set {
                source: ValueSource::Notes,
                secret: Zeroizing::new(b"pw".to_vec()),
                base_mark: [7; 32],
                owned: false,
            },
            answer: Some((HistoryQuestion::EvictsForeign, HistoryAnswer::KeepSeparate)),
        };
        let back = unseal(&seal(&Queue { ops: vec![CoreOp::Patch(patch)], registry: vec![] }, &key), &key).unwrap();
        let CoreOp::Patch(p) = &back.ops[0] else { panic!("expected Patch") };
        assert_eq!((p.id.as_str(), p.base_revision.as_str()), ("pid", "r1"));
        assert_eq!(p.cipher_id.as_deref(), Some("c1"));
        assert_eq!(
            p.set.iter().map(|f| (f.name.as_str(), f.value.as_str(), f.hidden)).collect::<Vec<_>>(),
            [("bwss:label", "l", false)]
        );
        assert_eq!(p.remove, ["bwss:attr:"]);
        let [a] = p.append_lines.as_slice() else { panic!("one line append") };
        assert_eq!((a.name.as_str(), a.lines[0].as_str(), a.hidden), ("bwss:acl", "/bin/a", true));
        assert!(matches!(&p.value, ValueChange::Set { source: ValueSource::Notes, secret, base_mark, .. }
            if secret.as_slice() == b"pw" && *base_mark == [7; 32]));
        assert_eq!(p.answer, Some((HistoryQuestion::EvictsForeign, HistoryAnswer::KeepSeparate)));
    }

    #[test]
    fn value_sources_keep_their_old_names_in_the_file() {
        for (source, old) in [
            (ValueSource::Field, "Field"),
            (ValueSource::Notes, "BwssNotes"),
            (ValueSource::NoteBody, "NoteBody"),
            (ValueSource::LoginPassword, "LoginPassword"),
        ] {
            let sealed = serde_json::to_value(SealedSource::from(source)).unwrap();
            assert_eq!(sealed, serde_json::json!(old));
            assert_eq!(ValueSource::from(serde_json::from_value::<SealedSource>(sealed).unwrap()), source);
        }
    }

    #[test]
    fn ops_queued_before_cipher_ids_still_open() {
        let key = key();
        let old = br#"[{"Delete":{"id":"a","base_revision":"r"}},
            {"Patch":{"id":"b","base_revision":"r","set":[["bwss:label","l",false]],"remove":[],"acl_add":["/x"],
              "value":{"Set":{"source":"BwssNotes","secret":[1],"base_mark":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}}}]"#;
        let file = serde_json::json!({ "format": 2, "ops": key.encrypt(old, &OsRandom).unwrap() });
        let back = unseal(&file, &key).unwrap();
        assert!(matches!(&back.ops[0], CoreOp::Delete { cipher_id: None, .. }));
        let CoreOp::Patch(p) = &back.ops[1] else { panic!("expected Patch") };
        assert!(p.cipher_id.is_none() && p.answer.is_none());
        assert!(matches!(p.value, ValueChange::Set { source: ValueSource::Notes, owned: false, .. }));
        assert_eq!(p.append_lines[0].lines[0].as_str(), "/x");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = key();
        let mut sealed = seal(&Queue { ops: vec![delete("a", None)], registry: vec![] }, &key);
        let mut enc = sealed["ops"].as_str().unwrap().to_string();
        let last = enc.pop().unwrap();
        enc.push(if last == 'A' { 'B' } else { 'A' });
        sealed["ops"] = Value::String(enc);
        assert!(unseal(&sealed, &key).is_err());
    }

    #[test]
    fn old_format_number_is_renamed_as_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("queue.json");
        std::fs::write(&p, r#"{"format":1}"#).unwrap();
        assert!(matches!(read_versioned(&p, "legacy"), Loaded::SetAside(_)));
        assert!(dir.path().join("queue.json.legacy").exists());
    }
}
