//! Backend-independent data model of the keyring.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

pub type Attributes = BTreeMap<String, String>;

/// Collection that always exists, maps to the root Bitwarden folder and
/// carries the `default` alias.
pub const LOGIN_COLLECTION: &str = "login";
/// In-memory collection for secrets that must not be persisted.
pub const SESSION_COLLECTION: &str = "session";
/// Read-only collection holding the rest of the Bitwarden vault (`whole_vault`).
pub const VAULT_COLLECTION: &str = "vault";

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
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub collections: Vec<CollectionData>,
    pub items: Vec<ItemData>,
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Turns any string into a valid D-Bus object path element.
pub fn path_segment(raw: &str) -> String {
    let s: String = raw.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    if s.is_empty() { "_".into() } else { s }
}

pub fn new_item_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
