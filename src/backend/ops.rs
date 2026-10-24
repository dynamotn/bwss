//! Queued writes and versioned state files.
//!
//! Queued ops hold secrets, ids and labels, so the whole list is sealed with
//! the user key (design §8.1, stricter: op kinds are hidden too). State files
//! carry `"format": 2`; anything older is set aside, never overwritten.

// Task 10 wires the queue into the Bitwarden backend.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::bw::crypto::{CryptoError, SymmetricKey};
use crate::bw::write::Patch;
use crate::model::ItemData;

use super::registry::Entry;

const FORMAT: u64 = 2;

pub enum Op {
    Create { id: String, collection: String, item: ItemData },
    Patch(Patch),
    Delete { id: String, base_revision: String },
    Registry { collection: String, entry: Entry },
}

pub enum Loaded<T> {
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
    secret: Vec<u8>,
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
            secret: i.secret.to_vec(),
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
            secret: Zeroizing::new(i.secret),
            content_type: i.content_type,
            created: i.created,
            modified: i.modified,
            acl: i.acl,
        }
    }
}

#[derive(Serialize, Deserialize)]
enum SealedOp {
    Create { id: String, collection: String, item: SealedItem },
    Patch(Patch),
    Delete { id: String, base_revision: String },
    Registry { collection: String, entry: Entry },
}

impl From<&Op> for SealedOp {
    fn from(op: &Op) -> Self {
        match op {
            Op::Create { id, collection, item } => {
                Self::Create { id: id.clone(), collection: collection.clone(), item: item.into() }
            }
            Op::Patch(p) => Self::Patch(p.clone()),
            Op::Delete { id, base_revision } => Self::Delete { id: id.clone(), base_revision: base_revision.clone() },
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
            SealedOp::Delete { id, base_revision } => Self::Delete { id, base_revision },
            SealedOp::Registry { collection, entry } => Self::Registry { collection, entry },
        }
    }
}

/// Seals the whole op list as one EncString under `"ops"`; only `"format"`
/// stays plain.
pub fn seal(ops: &[Op], key: &SymmetricKey) -> Value {
    let mirror: Vec<SealedOp> = ops.iter().map(SealedOp::from).collect();
    let json = Zeroizing::new(serde_json::to_vec(&mirror).expect("ops serialize to JSON"));
    serde_json::json!({ "format": FORMAT, "ops": key.encrypt(&json) })
}

/// Opens a sealed op list. A wrong key or tampered data is an error; the
/// caller decides what to do with the file.
pub fn unseal(file: &Value, key: &SymmetricKey) -> Result<Vec<Op>, CryptoError> {
    if file.get("format").and_then(Value::as_u64) != Some(FORMAT) {
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
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Loaded::Missing,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "cannot read state file");
            return Loaded::Missing;
        }
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(v) if v.get("format").and_then(Value::as_u64) == Some(FORMAT) => Loaded::Ok(v),
        Ok(_) => set_aside(path, legacy_suffix),
        Err(_) => set_aside(path, "corrupt"),
    }
}

fn set_aside(path: &Path, suffix: &str) -> Loaded<Value> {
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
            Loaded::Missing
        }
    }
}

#[cfg(test)]
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

    #[test]
    fn sealed_queue_round_trips_and_hides_secrets() {
        let key = SymmetricKey::generate();
        let ops = vec![
            Op::Create { id: "id-7f3a-unique".into(), collection: "default".into(), item: item() },
            Op::Delete { id: "id-7f3a-unique".into(), base_revision: "rev".into() },
            Op::Registry {
                collection: "c".into(),
                entry: Entry { label: "label-xyzzy-unique".into(), created: 3, deleted: false },
            },
        ];
        let sealed = seal(&ops, &key);
        assert_eq!(sealed["format"], 2);
        let text = sealed.to_string();
        for needle in ["s3cr3t-plumb-unique", "id-7f3a-unique", "label-xyzzy-unique"] {
            assert!(!text.contains(needle), "{needle} leaked");
        }
        let back = unseal(&sealed, &key).unwrap();
        assert_eq!(back.len(), 3);
        match &back[0] {
            Op::Create { id, collection, item: got } => {
                assert_eq!(id, "id-7f3a-unique");
                assert_eq!(collection, "default");
                assert_eq!(*got, item());
            }
            _ => panic!("wrong op"),
        }
        assert!(matches!(&back[1], Op::Delete { base_revision, .. } if base_revision == "rev"));
        assert!(matches!(&back[2], Op::Registry { entry, .. } if entry.created == 3));
        assert!(unseal(&sealed, &SymmetricKey::generate()).is_err());
        assert!(matches!(unseal(&serde_json::json!({"ops": "x"}), &key), Err(CryptoError::Malformed)));
    }

    #[test]
    fn legacy_queue_is_renamed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("queue.json");
        std::fs::write(&p, r#"{"ops":[]}"#).unwrap();
        match read_versioned(&p, "legacy") {
            Loaded::SetAside(to) => assert_eq!(to, dir.path().join("queue.json.legacy")),
            _ => panic!("expected SetAside"),
        }
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
        match read_versioned(&p, "legacy") {
            Loaded::SetAside(to) => assert_eq!(to, dir.path().join("queue.json.corrupt.1")),
            _ => panic!("expected SetAside"),
        }
    }

    #[test]
    fn current_format_loads_and_missing_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("queue.json");
        assert!(matches!(read_versioned(&p, "legacy"), Loaded::Missing));
        std::fs::write(&p, r#"{"format":2,"ops":"x"}"#).unwrap();
        assert!(matches!(read_versioned(&p, "legacy"), Loaded::Ok(v) if v["format"] == 2));
    }
}
