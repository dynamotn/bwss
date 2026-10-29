//! In-memory keyring state: collections, items, lock state and search.
//!
//! While locked, the decrypted items are gone. To let clients find what they
//! need to unlock (libsecret only unlocks items that a search reported as
//! locked), a *locked index* of salted attribute hashes is kept on disk, the
//! same trade-off gnome-keyring makes: it reveals which items exist and lets
//! someone with the file test guesses of attribute values, never secrets.
//! Derived attributes (item name, username, URI, id) are left out unless
//! this device opted in (design §7).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bw::fields::DERIVED;
use crate::model::{Attributes, CollectionData, ItemData, LOGIN_COLLECTION, SESSION_COLLECTION, Snapshot, now};

/// Version of the locked index file; an index of another version is not
/// read. Format 2 mixed derived attributes in with the others.
const INDEX_FORMAT: u64 = 3;

#[derive(Debug, Default, Serialize, Deserialize)]
struct LockedIndexFile {
    #[serde(default)]
    format: u64,
    salt: String,
    collections: Vec<IndexedCollection>,
    items: Vec<IndexedItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexedCollection {
    id: String,
    label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexedItem {
    id: String,
    collection: String,
    /// Hashes of the attributes the app set.
    attrs: BTreeSet<String>,
    /// Hashes of the derived attributes, only when this device opted in.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    derived: BTreeSet<String>,
    /// The cipher it was read from, to hold it while that cipher is a blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cipher: Option<String>,
}

/// What changed when a new snapshot replaced the old one.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub created: Vec<(String, String)>,
    pub changed: Vec<(String, String)>,
    pub deleted: Vec<(String, String)>,
    pub collections_created: Vec<String>,
    pub collections_deleted: Vec<String>,
}

/// (collection id, item id)
pub type ItemRef = (String, String);

pub struct Keyring {
    unlocked: bool,
    collections: BTreeMap<String, CollectionData>,
    items: BTreeMap<String, ItemData>,
    index: LockedIndexFile,
    /// `index.salt`, decoded once when the index is loaded.
    salt: [u8; 32],
    index_path: Option<PathBuf>,
    /// The device flag that puts derived attributes in the index.
    derived_flag: Option<PathBuf>,
    /// Whether the flag was set at start or at the last index write.
    index_derived: bool,
    /// Index entries of items whose cipher is now blob-encrypted (cannot be
    /// inspected): kept, locked, until the cipher is gone or trashed.
    held: Vec<IndexedItem>,
    /// Item id to cipher id, from the last snapshot.
    cipher_of: BTreeMap<String, String>,
}

fn builtin_collections() -> BTreeMap<String, CollectionData> {
    let t = now();
    let mut m = BTreeMap::new();
    m.insert(
        LOGIN_COLLECTION.into(),
        CollectionData { id: LOGIN_COLLECTION.into(), label: "Login".into(), created: t, modified: t },
    );
    m.insert(
        SESSION_COLLECTION.into(),
        CollectionData { id: SESSION_COLLECTION.into(), label: "Session".into(), created: t, modified: t },
    );
    m
}

impl Keyring {
    /// The keyring, locked, with the index kept in `index_path`. Derived
    /// attributes go in the index while the file `derived_flag` exists; it
    /// is read now and at every index write.
    pub fn new(index_path: Option<PathBuf>, derived_flag: Option<PathBuf>) -> Self {
        let index_derived = derived_flag.as_deref().is_some_and(crate::config::flag_set);
        let decode = |i: &LockedIndexFile| <[u8; 32]>::try_from(B64.decode(&i.salt).ok()?).ok();
        let bytes = index_path.as_ref().and_then(|p| std::fs::read(p).ok());
        let stored = bytes
            .as_deref()
            .and_then(|b| serde_json::from_slice::<LockedIndexFile>(b).ok())
            .filter(|i| i.format == INDEX_FORMAT)
            .and_then(|i| decode(&i).map(|salt| (i, salt)));
        // An index that cannot be used, or holds derived attributes this
        // device no longer wants, leaves the disk now, not at the next unlock.
        let mut rewrite = bytes.is_some() && stored.is_none();
        let (mut index, salt) = stored.unwrap_or_else(|| {
            let mut salt = [0u8; 32];
            rand::fill(&mut salt);
            (LockedIndexFile { format: INDEX_FORMAT, salt: B64.encode(salt), ..Default::default() }, salt)
        });
        if !index_derived {
            for item in index.items.iter_mut().filter(|i| !i.derived.is_empty()) {
                item.derived.clear();
                rewrite = true;
            }
        }
        if rewrite && let Some(path) = &index_path {
            write_index(path, &index);
        }
        let mut collections = builtin_collections();
        for c in &index.collections {
            collections.entry(c.id.clone()).or_insert_with(|| CollectionData {
                id: c.id.clone(),
                label: c.label.clone(),
                created: 0,
                modified: 0,
            });
        }
        Keyring {
            unlocked: false,
            collections,
            items: BTreeMap::new(),
            index,
            salt,
            index_path,
            derived_flag,
            index_derived,
            held: Vec::new(),
            cipher_of: BTreeMap::new(),
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked
    }

    /// The session collection never locks: it lives only in memory.
    pub fn collection_locked(&self, id: &str) -> bool {
        id != SESSION_COLLECTION && !self.unlocked
    }

    pub fn collections(&self) -> impl Iterator<Item = &CollectionData> {
        self.collections.values()
    }

    pub fn collection(&self, id: &str) -> Option<&CollectionData> {
        self.collections.get(id)
    }

    /// Every item known, locked ones included, as (collection, id).
    pub fn item_refs(&self) -> Vec<(String, String)> {
        let mut out: BTreeSet<(String, String)> =
            self.items.values().map(|i| (i.collection.clone(), i.id.clone())).collect();
        let indexed = if self.unlocked { &self.held } else { &self.index.items };
        out.extend(indexed.iter().map(|i| (i.collection.clone(), i.id.clone())));
        out.into_iter().collect()
    }

    pub fn items_in(&self, collection: &str) -> Vec<String> {
        self.item_refs().into_iter().filter(|(c, _)| c == collection).map(|(_, id)| id).collect()
    }

    /// The item, if it is known and unlocked.
    pub fn item(&self, id: &str) -> Option<&ItemData> {
        self.items.get(id)
    }

    pub fn item_locked(&self, id: &str) -> bool {
        match self.items.get(id) {
            Some(i) => self.collection_locked(&i.collection),
            None => true,
        }
    }

    fn hash_attr(&self, name: &str, value: &str) -> String {
        let mut h = Sha256::new();
        h.update(self.salt);
        h.update(name.as_bytes());
        h.update([0]);
        h.update(value.as_bytes());
        hex::encode(h.finalize())
    }

    /// (unlocked, locked) item refs matching all attributes.
    pub fn search(&self, query: &Attributes, collection: Option<&str>) -> (Vec<ItemRef>, Vec<ItemRef>) {
        let in_scope = |c: &str| collection.is_none_or(|want| want == c);
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();
        for item in self.items.values().filter(|i| in_scope(&i.collection) && i.matches(query)) {
            let r = (item.collection.clone(), item.id.clone());
            if self.collection_locked(&item.collection) { locked.push(r) } else { unlocked.push(r) }
        }
        {
            let wanted: BTreeSet<String> = query.iter().map(|(k, v)| self.hash_attr(k, v)).collect();
            let indexed =
                |e: &IndexedItem, h: &String| e.attrs.contains(h) || (self.index_derived && e.derived.contains(h));
            let entries = if self.unlocked { &self.held } else { &self.index.items };
            for e in entries.iter().filter(|e| in_scope(&e.collection) && wanted.iter().all(|h| indexed(e, h))) {
                locked.push((e.collection.clone(), e.id.clone()));
            }
        }
        (unlocked, locked)
    }

    /// Replaces the persistent contents with a backend snapshot (after unlock
    /// or refresh) and reports what clients should be told about.
    pub fn load(&mut self, snap: Snapshot) -> Diff {
        let was_unlocked = self.unlocked;
        let old_refs: BTreeSet<(String, String)> = self.item_refs().into_iter().collect();
        let old_collections: BTreeSet<String> = self.collections.keys().cloned().collect();

        let mut collections = builtin_collections();
        if let Some(s) = self.collections.get(SESSION_COLLECTION) {
            collections.insert(SESSION_COLLECTION.into(), s.clone());
        }
        for c in snap.collections {
            collections.insert(c.id.clone(), c);
        }
        self.collections = collections;

        let previous = std::mem::take(&mut self.items);
        let mut items: BTreeMap<String, ItemData> = previous
            .iter()
            .filter(|(_, i)| i.collection == SESSION_COLLECTION)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for item in snap.items.into_iter().filter(|i| self.collections.contains_key(&i.collection)) {
            items.insert(item.id.clone(), item);
        }
        self.items = items;
        // Items whose cipher is a blob now cannot be read, but are not gone.
        let candidates = if was_unlocked { std::mem::take(&mut self.held) } else { self.index.items.clone() };
        self.held = candidates
            .into_iter()
            .filter(|e| !self.items.contains_key(&e.id) && self.collections.contains_key(&e.collection))
            .filter(|e| e.cipher.as_ref().is_some_and(|c| snap.blobs.contains(c)))
            .collect();
        self.cipher_of = snap.ciphers;
        self.unlocked = true;
        let new_refs: BTreeSet<(String, String)> = self.item_refs().into_iter().collect();

        // Changes are only known when the old values were (i.e. on a refresh).
        let changed = if was_unlocked {
            new_refs.intersection(&old_refs).filter(|(_, id)| previous.get(id) != self.items.get(id)).cloned().collect()
        } else {
            Vec::new()
        };
        let diff = Diff {
            created: new_refs.difference(&old_refs).cloned().collect(),
            deleted: old_refs.difference(&new_refs).cloned().collect(),
            changed,
            collections_created: self.collections.keys().filter(|c| !old_collections.contains(*c)).cloned().collect(),
            collections_deleted: old_collections
                .iter()
                .filter(|c| !self.collections.contains_key(*c))
                .cloned()
                .collect(),
        };
        self.save_index();
        diff
    }

    /// Drops all decrypted state except the session collection.
    pub fn lock(&mut self) {
        self.items.retain(|_, i| i.collection == SESSION_COLLECTION);
        self.unlocked = false;
    }

    /// Stores the item. While locked only the session collection takes
    /// items; any other is dropped and `false` returned.
    pub fn upsert(&mut self, item: ItemData) -> bool {
        if self.collection_locked(&item.collection) {
            return false;
        }
        self.items.insert(item.id.clone(), item);
        self.save_index();
        true
    }

    pub fn remove(&mut self, id: &str) -> Option<ItemData> {
        let r = self.items.remove(id);
        self.save_index();
        r
    }

    pub fn add_collection(&mut self, c: CollectionData) {
        self.collections.insert(c.id.clone(), c);
        self.save_index();
    }

    pub fn remove_collection(&mut self, id: &str) -> Vec<String> {
        self.collections.remove(id);
        let gone: Vec<String> = self.items.values().filter(|i| i.collection == id).map(|i| i.id.clone()).collect();
        for g in &gone {
            self.items.remove(g);
        }
        self.save_index();
        gone
    }

    pub fn set_collection_label(&mut self, id: &str, label: &str) {
        if let Some(c) = self.collections.get_mut(id) {
            c.label = label.to_owned();
            c.modified = now();
        }
        self.save_index();
    }

    fn save_index(&mut self) {
        if !self.unlocked {
            return;
        }
        self.index_derived = self.derived_flag.as_deref().is_some_and(crate::config::flag_set);
        let items = self
            .items
            .values()
            .filter(|i| i.collection != SESSION_COLLECTION)
            .map(|i| {
                let (derived, own): (Vec<_>, Vec<_>) =
                    i.attributes.iter().partition(|(k, _)| DERIVED.contains(&k.as_str()));
                IndexedItem {
                    id: i.id.clone(),
                    collection: i.collection.clone(),
                    attrs: own.into_iter().map(|(k, v)| self.hash_attr(k, v)).collect(),
                    cipher: self.cipher_of.get(&i.id).cloned(),
                    derived: if self.index_derived {
                        derived.into_iter().map(|(k, v)| self.hash_attr(k, v)).collect()
                    } else {
                        BTreeSet::new()
                    },
                }
            })
            .chain(self.held.iter().cloned())
            .collect();
        let collections = self
            .collections
            .values()
            .filter(|c| c.id != SESSION_COLLECTION && c.id != LOGIN_COLLECTION)
            .map(|c| IndexedCollection { id: c.id.clone(), label: c.label.clone() })
            .collect();
        self.index.items = items;
        self.index.collections = collections;
        if let Some(path) = &self.index_path {
            write_index(path, &self.index);
        }
    }
}

fn write_index(path: &std::path::Path, index: &LockedIndexFile) {
    if let Err(e) = crate::fsutil::write_json_private(path, index) {
        tracing::warn!("could not save the locked index: {e}");
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn item(id: &str, collection: &str, attrs: &[(&str, &str)]) -> ItemData {
        ItemData {
            id: id.into(),
            collection: collection.into(),
            label: id.into(),
            attributes: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            secret: Zeroizing::new(b"s".to_vec()),
            content_type: "text/plain".into(),
            created: 1,
            modified: 1,
            acl: vec![],
        }
    }

    fn q(attrs: &[(&str, &str)]) -> Attributes {
        attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn search_unlocked_and_locked_through_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        let mut k = Keyring::new(Some(path.clone()), None);
        k.load(Snapshot {
            collections: vec![],
            items: vec![
                item("a", "login", &[("service", "gh"), ("user", "me")]),
                item("b", "login", &[("service", "x")]),
            ],
            ..Default::default()
        });
        assert_eq!(k.search(&q(&[("service", "gh")]), None).0, vec![("login".into(), "a".into())]);
        k.lock();
        assert!(k.item("a").is_none());

        // A fresh daemon (restart) still finds locked items, but never the secret.
        let k2 = Keyring::new(Some(path.clone()), None);
        let (unlocked, locked) = k2.search(&q(&[("service", "gh")]), None);
        assert!(unlocked.is_empty());
        assert_eq!(locked, vec![("login".into(), "a".into())]);
        assert!(k2.search(&q(&[("service", "nope")]), None).1.is_empty());
        let text = std::fs::read_to_string(&path).unwrap();
        // Quoted: the random base64 salt may contain the bare letters.
        assert!(!text.contains("\"gh\"") && !text.contains("\"me\""));
    }

    #[test]
    fn blob_ciphers_stay_in_the_index_across_an_unlock_until_they_are_gone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        let r = |c: &str, i: &str| (c.to_owned(), i.to_owned());
        let mut k = Keyring::new(Some(path.clone()), None);
        let ciphers = [("a".to_owned(), "c1".to_owned()), ("b".to_owned(), "c2".to_owned())].into();
        k.load(Snapshot {
            items: vec![item("a", "login", &[("service", "gh")]), item("b", "login", &[("service", "x")])],
            ciphers,
            ..Default::default()
        });
        k.lock();

        // Another client turned c1 into a blob: it cannot be read, not gone.
        let mut k = Keyring::new(Some(path.clone()), None);
        let blobs = ["c1".to_owned()].into();
        let diff = k.load(Snapshot { items: vec![], blobs, ..Default::default() });
        assert_eq!(diff.deleted, [r("login", "b")]);
        assert_eq!(k.item_refs(), [r("login", "a")]);
        assert_eq!(k.search(&q(&[("service", "gh")]), None).1, [r("login", "a")], "found as locked");
        k.lock();
        let mut k = Keyring::new(Some(path.clone()), None);
        assert_eq!(k.item_refs(), [r("login", "a")], "and still in the index on disk");

        // A refresh that still sees the blob keeps it; once the cipher is gone, it is deleted.
        let blobs = ["c1".to_owned()].into();
        assert!(k.load(Snapshot { blobs, ..Default::default() }).deleted.is_empty());
        let diff = k.load(Snapshot::default());
        assert_eq!(diff.deleted, [r("login", "a")]);
        assert!(k.item_refs().is_empty());
    }

    fn read_json(path: &std::path::Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn an_index_of_another_format_is_ignored_and_replaced_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        let mut k = Keyring::new(Some(path.clone()), None);
        k.load(Snapshot {
            collections: vec![],
            items: vec![item("a", "login", &[("service", "gh")])],
            ..Default::default()
        });
        let mut saved = read_json(&path);
        assert_eq!(saved["format"], 3);
        assert_eq!(Keyring::new(Some(path.clone()), None).search(&q(&[("service", "gh")]), None).1.len(), 1);

        // Format 2 mixed derived attributes in: it is not read, and it
        // leaves the disk when the daemon starts, not at the next unlock.
        for older in [Some(2), None] {
            match older {
                Some(f) => saved["format"] = f.into(),
                None => drop(saved.as_object_mut().unwrap().remove("format")),
            }
            std::fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
            let old = Keyring::new(Some(path.clone()), None);
            assert!(old.search(&q(&[("service", "gh")]), None).1.is_empty());
            assert_ne!(old.index.salt, saved["salt"].as_str().unwrap());
            let replaced = read_json(&path);
            assert_eq!(replaced["format"], 3);
            assert_eq!(replaced["salt"].as_str().unwrap(), old.index.salt);
            assert_eq!(replaced["items"], serde_json::json!([]));
        }
    }

    fn collection(id: &str, label: &str) -> CollectionData {
        CollectionData { id: id.into(), label: label.into(), created: 1, modified: 1 }
    }

    #[test]
    fn renaming_a_collection_updates_it_and_the_locked_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        let mut k = Keyring::new(Some(path.clone()), None);
        k.load(Snapshot { collections: vec![collection("work", "Work")], items: vec![], ..Default::default() });
        assert_eq!(read_json(&path)["collections"][0]["label"], "Work");

        k.set_collection_label("work", "Office");
        let c = k.collection("work").unwrap();
        assert_eq!(c.label, "Office");
        assert!(c.modified > 1, "the modification time moves");
        assert_eq!(read_json(&path)["collections"][0]["label"], "Office");

        let before = k.collections().count();
        k.set_collection_label("nope", "Ghost");
        assert!(k.collection("nope").is_none(), "an unknown collection is not created");
        assert_eq!(k.collections().count(), before);
        assert_eq!(read_json(&path)["collections"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn an_index_that_cannot_be_saved_leaves_the_keyring_working() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let mut k = Keyring::new(Some(blocker.join("index.json")), None);
        k.load(Snapshot {
            collections: vec![],
            items: vec![item("a", "login", &[("service", "gh")])],
            ..Default::default()
        });
        assert_eq!(k.search(&q(&[("service", "gh")]), None).0, vec![("login".into(), "a".into())]);
        assert_eq!(std::fs::read(&blocker).unwrap(), b"x");
        // Later changes and a reload keep working too.
        assert!(k.upsert(item("b", "login", &[("service", "gl")])));
        k.load(Snapshot {
            collections: vec![],
            items: vec![item("c", "login", &[("service", "gl")])],
            ..Default::default()
        });
        assert_eq!(k.search(&q(&[("service", "gl")]), None).0, vec![("login".into(), "c".into())]);
        assert!(k.search(&q(&[("service", "gh")]), None).0.is_empty(), "the reload replaced the content");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "nothing else was written beside it");
    }

    const DERIVED: [(&str, &str); 4] =
        [("bwss:id", "a"), ("bwss:name", "GitHub"), ("bwss:username", "me"), ("bwss:uri", "https://github.com")];

    fn derived_item() -> ItemData {
        let mut attrs = vec![("service", "gh")];
        attrs.extend(DERIVED);
        item("a", "login", &attrs)
    }

    /// How many attribute hashes the index file holds for its only item.
    fn hashes_on_disk(path: &std::path::Path) -> usize {
        let saved = read_json(path);
        let item = &saved["items"][0];
        ["attrs", "derived"].iter().map(|k| item[k].as_array().map_or(0, Vec::len)).sum()
    }

    #[test]
    fn derived_attributes_stay_out_of_the_locked_index_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        let flag = dir.path().join("index-derived");
        let mut k = Keyring::new(Some(path.clone()), Some(flag.clone()));
        k.load(Snapshot { collections: vec![], items: vec![derived_item()], ..Default::default() });
        // Unlocked, the item is still found by its derived attributes.
        assert_eq!(k.search(&q(&[("bwss:name", "GitHub")]), None).0.len(), 1);
        k.lock();
        assert_eq!(hashes_on_disk(&path), 1, "only the attribute the app set");

        let restarted = Keyring::new(Some(path.clone()), Some(flag));
        assert_eq!(restarted.search(&q(&[("service", "gh")]), None).1, vec![("login".into(), "a".into())]);
        for (name, value) in DERIVED {
            assert!(restarted.search(&q(&[(name, value)]), None).1.is_empty(), "{name}");
            assert!(restarted.search(&q(&[("service", "gh"), (name, value)]), None).1.is_empty(), "{name}");
        }
    }

    #[test]
    fn the_device_flag_indexes_derived_attributes_until_it_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        let flag = dir.path().join("index-derived");
        std::fs::write(&flag, "on\n").unwrap();
        let mut k = Keyring::new(Some(path.clone()), Some(flag.clone()));
        k.load(Snapshot { collections: vec![], items: vec![derived_item()], ..Default::default() });
        assert_eq!(hashes_on_disk(&path), 5);
        k.lock();
        let on = Keyring::new(Some(path.clone()), Some(flag.clone()));
        for (name, value) in DERIVED {
            assert_eq!(on.search(&q(&[("service", "gh"), (name, value)]), None).1.len(), 1, "{name}");
        }

        // Turned off while the daemon runs: the next index write drops them.
        std::fs::remove_file(&flag).unwrap();
        k.load(Snapshot { collections: vec![], items: vec![derived_item()], ..Default::default() });
        assert_eq!(hashes_on_disk(&path), 1);
        k.lock();
        assert!(k.search(&q(&[("bwss:name", "GitHub")]), None).1.is_empty());

        // Turned off while it was stopped: they leave the disk at start.
        std::fs::write(&flag, "on\n").unwrap();
        k.load(Snapshot { collections: vec![], items: vec![derived_item()], ..Default::default() });
        assert_eq!(hashes_on_disk(&path), 5);
        std::fs::remove_file(&flag).unwrap();
        let off = Keyring::new(Some(path.clone()), Some(flag));
        assert_eq!(hashes_on_disk(&path), 1);
        assert!(off.search(&q(&[("bwss:name", "GitHub")]), None).1.is_empty());
        assert_eq!(off.search(&q(&[("service", "gh")]), None).1.len(), 1, "the rest of the index is kept");
    }

    #[test]
    fn diff_after_refresh() {
        let mut k = Keyring::new(None, None);
        k.load(Snapshot {
            collections: vec![],
            items: vec![item("a", "login", &[]), item("b", "login", &[])],
            ..Default::default()
        });
        let mut changed = item("a", "login", &[]);
        changed.label = "renamed".into();
        let d = k.load(Snapshot {
            collections: vec![],
            items: vec![changed, item("c", "login", &[])],
            ..Default::default()
        });
        assert_eq!(d.changed, vec![("login".into(), "a".into())]);
        assert_eq!(d.created, vec![("login".into(), "c".into())]);
        assert_eq!(d.deleted, vec![("login".into(), "b".into())]);
    }

    #[test]
    fn session_collection_is_never_locked_or_persisted() {
        let mut k = Keyring::new(None, None);
        k.upsert(item("tmp", SESSION_COLLECTION, &[("k", "v")]));
        k.lock();
        assert!(!k.item_locked("tmp"));
        assert_eq!(k.search(&q(&[("k", "v")]), None).0.len(), 1);
        k.load(Snapshot::default());
        assert!(k.item("tmp").is_some());
    }

    #[test]
    fn upsert_after_lock_keeps_nothing() {
        let mut k = Keyring::new(None, None);
        k.load(Snapshot { collections: vec![], items: vec![item("a", "login", &[])], ..Default::default() });
        k.lock();
        assert!(!k.upsert(item("late", "login", &[("k", "v")])));
        assert!(k.item("late").is_none());
        assert!(k.items.is_empty());
        assert!(k.upsert(item("tmp", SESSION_COLLECTION, &[])));
        assert!(k.item("tmp").is_some());
    }
}
