//! Queued writes and versioned state files.
//!
//! Queued ops hold secrets, ids and labels, so the whole list is sealed with
//! the queue key (design §8.1, stricter: op kinds are hidden too). State
//! files carry `"format": 2` (the queue: 3); anything older is set aside,
//! never overwritten.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::bw::crypto::{CryptoError, SymmetricKey};
use crate::bw::write::Patch;
use crate::model::ItemData;

use super::registry::Entry;

pub(crate) const FORMAT: u64 = 2;
/// `queue.json` sealed with the queue key. Format 2 was sealed with the user
/// key itself and is opened only during the one-time migration.
pub(crate) const QUEUE_FORMAT: u64 = 3;

/// A queued write. A delete's `cipher_id` is the cipher it was read from,
/// when known.
#[derive(Clone)]
pub enum Op {
    Create { id: String, collection: String, item: ItemData },
    Patch(Patch),
    Delete { id: String, base_revision: String, cipher_id: Option<String> },
    Registry { collection: String, entry: Entry },
}

/// Result of reading a state file.
///
/// On `Unreadable` the file is still in place and may hold data (for example
/// queued writes): callers must not overwrite or delete it.
pub enum Loaded<T> {
    /// The file could not be read or set aside.
    Unreadable(std::io::Error),
    Ok(T),
    Missing,
    SetAside(PathBuf),
}

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

impl From<&ItemData> for SealedItem {
    fn from(i: &ItemData) -> Self {
        Self {
            id: i.id.clone(),
            collection: i.collection.clone(),
            label: i.label.clone(),
            attributes: i.attributes.clone(),
            secret: Zeroizing::new(i.secret.to_vec()),
            content_type: i.content_type.clone(),
            created: i.created,
            modified: i.modified,
            acl: i.acl.clone(),
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

#[derive(Serialize, Deserialize)]
enum SealedOp {
    Create {
        id: String,
        collection: String,
        item: SealedItem,
    },
    Patch(Patch),
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

impl From<&Op> for SealedOp {
    fn from(op: &Op) -> Self {
        match op {
            Op::Create { id, collection, item } => {
                Self::Create { id: id.clone(), collection: collection.clone(), item: item.into() }
            }
            Op::Patch(p) => Self::Patch(p.clone()),
            Op::Delete { id, base_revision, cipher_id } => {
                Self::Delete { id: id.clone(), base_revision: base_revision.clone(), cipher_id: cipher_id.clone() }
            }
            Op::Registry { collection, entry } => {
                Self::Registry { collection: collection.clone(), entry: entry.clone() }
            }
        }
    }
}

impl From<SealedOp> for Op {
    fn from(op: SealedOp) -> Self {
        match op {
            SealedOp::Create { id, collection, item } => Self::Create { id, collection, item: item.into() },
            SealedOp::Patch(p) => Self::Patch(p),
            SealedOp::Delete { id, base_revision, cipher_id } => Self::Delete { id, base_revision, cipher_id },
            SealedOp::Registry { collection, entry } => Self::Registry { collection, entry },
        }
    }
}

/// Seals the whole op list as one EncString under `"ops"`; only `"format"`
/// stays plain.
///
/// Known limitation: while `serde_json` serializes (here) and parses (in
/// `unseal`), its `Vec<u8>` growth can leave partial unwiped copies of the
/// queued secrets behind.
#[expect(clippy::expect_used, reason = "a Vec of plain derived-Serialize structs always serializes")]
pub fn seal(ops: &[Op], key: &SymmetricKey) -> Value {
    let mirror: Vec<SealedOp> = ops.iter().map(SealedOp::from).collect();
    let json = Zeroizing::new(serde_json::to_vec(&mirror).expect("ops serialize to JSON"));
    serde_json::json!({ "format": QUEUE_FORMAT, "ops": key.encrypt(&json) })
}

/// Opens a sealed op list. A wrong key or tampered data is an error; the
/// caller decides what to do with the file.
/// Which key may open which format is the caller's decision.
pub fn unseal(file: &Value, key: &SymmetricKey) -> Result<Vec<Op>, CryptoError> {
    if !matches!(file.get("format").and_then(Value::as_u64), Some(FORMAT | QUEUE_FORMAT)) {
        return Err(CryptoError::Malformed);
    }
    let enc = file.get("ops").and_then(Value::as_str).ok_or(CryptoError::Malformed)?;
    let plain = key.decrypt(enc)?;
    let mirror: Vec<SealedOp> = serde_json::from_slice(&plain).map_err(|_| CryptoError::Malformed)?;
    Ok(mirror.into_iter().map(Op::from).collect())
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
    use std::collections::BTreeMap;

    fn item() -> ItemData {
        ItemData {
            id: "id-7f3a-unique".into(),
            collection: "default".into(),
            label: "label-xyzzy-unique".into(),
            attributes: BTreeMap::from([("k".to_string(), "v".to_string())]),
            secret: Zeroizing::new(b"s3cr3t-plumb-unique".to_vec()),
            content_type: "text/plain".into(),
            created: 1,
            modified: 2,
            acl: vec!["/usr/bin/x".into()],
        }
    }

    /// Compiles only while queued secrets are wiped on drop.
    fn _assert_zeroizing(s: &SealedItem) -> &Zeroizing<Vec<u8>> {
        &s.secret
    }

    #[test]
    fn sealed_item_secret_is_zeroizing() {
        let sealed = SealedItem::from(&item());
        assert_eq!(_assert_zeroizing(&sealed).as_slice(), b"s3cr3t-plumb-unique");
        let back = ItemData::from(sealed);
        assert_eq!(back, item());
    }

    #[test]
    fn sealed_queue_round_trips_and_hides_secrets() {
        let key = SymmetricKey::generate();
        let ops = vec![
            Op::Create { id: "id-7f3a-unique".into(), collection: "default".into(), item: item() },
            Op::Delete { id: "id-7f3a-unique".into(), base_revision: "rev".into(), cipher_id: Some("c9".into()) },
            Op::Registry {
                collection: "c".into(),
                entry: Entry { label: "label-xyzzy-unique".into(), created: 3, deleted: false },
            },
        ];
        let sealed = seal(&ops, &key);
        assert_eq!(sealed["format"], 3);
        let text = sealed.to_string();
        for needle in ["s3cr3t-plumb-unique", "id-7f3a-unique", "label-xyzzy-unique"] {
            assert!(!text.contains(needle), "{needle} leaked");
        }
        let back = unseal(&sealed, &key).unwrap();
        assert_eq!(back.len(), 3);
        let Op::Create { id, collection, item: got } = &back[0] else { panic!() };
        assert_eq!(id, "id-7f3a-unique");
        assert_eq!(collection, "default");
        assert_eq!(*got, item());
        assert!(
            matches!(&back[1], Op::Delete { base_revision, cipher_id, .. } if base_revision == "rev" && cipher_id.as_deref() == Some("c9"))
        );
        assert!(matches!(&back[2], Op::Registry { entry, .. } if entry.created == 3));
        assert!(unseal(&sealed, &SymmetricKey::generate()).is_err());
        assert!(matches!(unseal(&serde_json::json!({"ops": "x"}), &key), Err(CryptoError::Malformed)));
    }

    #[test]
    fn legacy_queue_is_renamed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("queue.json");
        std::fs::write(&p, r#"{"ops":[]}"#).unwrap();
        let Loaded::SetAside(to) = read_versioned(&p, "legacy") else { panic!() };
        assert_eq!(to, dir.path().join("queue.json.legacy"));
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
        let Loaded::SetAside(to) = read_versioned(&p, "legacy") else { panic!() };
        assert_eq!(to, dir.path().join("queue.json.corrupt.1"));
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
        let Loaded::Unreadable(e) = set_aside(&p, "legacy") else { panic!() };
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        assert!(!dir.path().join("queue.json.legacy").exists());
    }

    #[test]
    fn patch_round_trips() {
        use crate::bw::scan::ValueSource;
        use crate::bw::write::ValueChange;
        let key = SymmetricKey::generate();
        let patch = Patch {
            id: "pid".into(),
            base_revision: "r1".into(),
            set: vec![("bwss:label".into(), "l".into(), false)],
            remove: vec!["bwss:attr:".into()],
            acl_add: vec!["/bin/a".into()],
            value: ValueChange::Set {
                source: ValueSource::Field,
                secret: b"pw".to_vec(),
                base_mark: [7; 32],
                owned: false,
            },
            cipher_id: Some("c1".into()),
        };
        let back = unseal(&seal(&[Op::Patch(patch)], &key), &key).unwrap();
        let Op::Patch(p) = &back[0] else { panic!() };
        assert_eq!((p.id.as_str(), p.base_revision.as_str()), ("pid", "r1"));
        assert_eq!(p.cipher_id.as_deref(), Some("c1"));
        assert_eq!(p.set, vec![("bwss:label".to_string(), "l".to_string(), false)]);
        assert_eq!(p.acl_add, vec!["/bin/a".to_string()]);
        assert!(
            matches!(&p.value, ValueChange::Set { secret, base_mark, .. } if secret == b"pw" && *base_mark == [7; 32])
        );
    }

    #[test]
    fn ops_queued_before_cipher_ids_still_open() {
        let key = SymmetricKey::generate();
        let old = br#"[{"Delete":{"id":"a","base_revision":"r"}},
            {"Patch":{"id":"b","base_revision":"r","set":[],"remove":[],"acl_add":[],"value":"Keep"}}]"#;
        let file = serde_json::json!({ "format": 2, "ops": key.encrypt(old) });
        let back = unseal(&file, &key).unwrap();
        assert!(matches!(&back[0], Op::Delete { cipher_id: None, .. }));
        assert!(matches!(&back[1], Op::Patch(p) if p.cipher_id.is_none()));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = SymmetricKey::generate();
        let mut sealed = seal(&[Op::Delete { id: "a".into(), base_revision: "r".into(), cipher_id: None }], &key);
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
