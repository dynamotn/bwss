//! Backend-independent data model of the keyring.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use zeroize::Zeroizing;

pub type Attributes = BTreeMap<String, String>;

/// Collection that always exists (items without `bwss:collection`) and
/// carries the `default` alias.
pub const LOGIN_COLLECTION: &str = "login";
/// In-memory collection for secrets that must not be persisted.
pub const SESSION_COLLECTION: &str = "session";

#[derive(Clone, PartialEq, Eq)]
pub struct ItemData {
    /// Stable id, shared by every device (stored in the item itself).
    pub id: String,
    pub collection: String,
    pub label: String,
    pub attributes: Attributes,
    pub secret: Zeroizing<Vec<u8>>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
    /// Executables allowed to use the item without asking.
    pub acl: Vec<String>,
}

impl std::fmt::Debug for ItemData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ItemData")
            .field("id", &self.id)
            .field("collection", &self.collection)
            .field("label", &self.label)
            .field("attributes", &self.attributes)
            .field("secret", &"<redacted>")
            .field("content_type", &self.content_type)
            .finish_non_exhaustive()
    }
}

impl ItemData {
    pub fn matches(&self, query: &Attributes) -> bool {
        query.iter().all(|(k, v)| self.attributes.get(k) == Some(v))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionData {
    pub id: String,
    pub label: String,
    pub created: u64,
    pub modified: u64,
}

/// Everything a backend knows once unlocked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub collections: Vec<CollectionData>,
    pub items: Vec<ItemData>,
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Reversibly turns any string into a valid D-Bus object path element:
/// ASCII letters and digits stay, every other byte becomes `_xx` (lowercase
/// hex) and the empty string becomes `_`.
pub fn escape_segment(raw: &str) -> String {
    if raw.is_empty() {
        return "_".into();
    }
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(b as char);
        } else {
            let _ = write!(out, "_{b:02x}");
        }
    }
    out
}

/// Inverse of [`escape_segment`]; `None` when `seg` is not a valid escape.
pub fn unescape_segment(seg: &str) -> Option<String> {
    if seg == "_" {
        return Some(String::new());
    }
    let bytes = seg.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        match c {
            b'_' => {
                let hex = seg.get(i + 1..i + 3)?;
                if !hex.bytes().all(|h| h.is_ascii_digit() || (b'a'..=b'f').contains(&h)) {
                    return None;
                }
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b if b.is_ascii_alphanumeric() => {
                out.push(b);
                i += 1;
            }
            _ => return None,
        }
    }
    String::from_utf8(out).ok()
}

pub fn new_item_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_is_reversible_and_collision_free() {
        for raw in ["0f3a9c", "github", "a_b", "a-b", "a b", "Work/Keys", "ü", ""] {
            let e = escape_segment(raw);
            assert!(e.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
            assert_eq!(unescape_segment(&e).as_deref(), Some(raw));
        }
        assert_ne!(escape_segment("a_b"), escape_segment("a-b"));
        assert_eq!(escape_segment("0123abcdef"), "0123abcdef");
        assert_eq!(escape_segment("a-b"), "a_2db");
        assert_eq!(unescape_segment("_zz"), None);
    }
}
