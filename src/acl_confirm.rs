//! Which ACL lines this device has confirmed (design §6).
//!
//! `bwss:acl` syncs with the item, so a line can come from another device,
//! or from anyone who can edit the item. A line counts on this device only
//! once the user confirmed it here: either it was granted here, or the user
//! answered the one-time question about it. A denial is remembered too.
//!
//! The file (`$XDG_STATE_HOME/dybw/tools/bwss/acl-confirmed`) is device
//! state, never synced. It holds tags, `HMAC(key, bwss:id ‖ 0x00 ‖ exe)`
//! under the user key derived for "acl-confirm", sealed as a whole with that
//! key like the write queue: `{ "format": 2, "set": "<EncString>" }`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::backend::ops::{FORMAT, Loaded, read_versioned};
use crate::bw::crypto::{SymmetricKey, acl_confirm_tag};
use crate::fsutil::write_json_private;

/// What this device decided about one ACL line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// Granted here, or confirmed here after it synced in.
    Confirmed,
    /// The user refused it here.
    Denied,
    /// Nothing recorded.
    None,
}

/// The sealed content: hex tags.
#[derive(Default, Serialize, Deserialize)]
struct Tags {
    confirmed: BTreeSet<String>,
    denied: BTreeSet<String>,
}

pub struct ConfirmSet {
    path: Option<PathBuf>,
    key: SymmetricKey,
    tags: Tags,
    /// False when the file exists but could not be read: it is never
    /// overwritten then, and decisions stay in memory.
    writable: bool,
}

impl ConfirmSet {
    /// Opens the set at `path` (`None`: memory only). A file that is not a
    /// `format: 2` document is set aside; one that cannot be read or opened
    /// with `key` reads as empty and is left alone.
    pub fn open(path: Option<PathBuf>, key: SymmetricKey) -> Self {
        let mut set = ConfirmSet { path, key, tags: Tags::default(), writable: true };
        let Some(path) = set.path.clone() else { return set };
        match read_versioned(&path, "old") {
            Loaded::Ok(file) => match set.unseal(&file) {
                Some(tags) => set.tags = tags,
                None => {
                    tracing::warn!(path = %path.display(), "cannot open the ACL confirmations; leaving the file alone");
                    set.writable = false;
                }
            },
            // Logged by `read_versioned`.
            Loaded::Unreadable(_) => set.writable = false,
            Loaded::Missing | Loaded::SetAside(_) => {}
        }
        set
    }

    fn unseal(&self, file: &Value) -> Option<Tags> {
        let plain = self.key.decrypt(file.get("set")?.as_str()?).ok()?;
        serde_json::from_slice(&plain).ok()
    }

    fn tag(&self, id: &str, exe: &str) -> String {
        hex::encode(acl_confirm_tag(&self.key, id, exe))
    }

    /// What this device decided about `exe`'s line in the item `id`.
    pub fn mark(&self, id: &str, exe: &str) -> Mark {
        let tag = self.tag(id, exe);
        if self.tags.confirmed.contains(&tag) {
            Mark::Confirmed
        } else if self.tags.denied.contains(&tag) {
            Mark::Denied
        } else {
            Mark::None
        }
    }

    /// Records a decision (`Mark::None` forgets it) and saves the set.
    pub fn set(&mut self, id: &str, exe: &str, mark: Mark) {
        if self.mark(id, exe) == mark {
            return;
        }
        let tag = self.tag(id, exe);
        self.tags.confirmed.remove(&tag);
        self.tags.denied.remove(&tag);
        match mark {
            Mark::Confirmed => self.tags.confirmed.insert(tag),
            Mark::Denied => self.tags.denied.insert(tag),
            Mark::None => false,
        };
        self.save();
    }

    #[expect(clippy::expect_used, reason = "two sets of strings always serialize")]
    fn save(&self) {
        let Some(path) = &self.path else { return };
        if !self.writable {
            tracing::warn!(path = %path.display(), "ACL decision kept in memory only: the file on disk could not be read");
            return;
        }
        let plain = serde_json::to_vec(&self.tags).expect("tags serialize");
        let file = serde_json::json!({ "format": FORMAT, "set": self.key.encrypt(&plain) });
        if let Err(e) = write_json_private(path, &file) {
            tracing::warn!(path = %path.display(), "could not save the ACL confirmations: {e}");
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    fn path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("dybw/tools/bwss/acl-confirmed")
    }

    #[test]
    fn marks_round_trip_through_the_sealed_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = SymmetricKey::generate();
        let mut set = ConfirmSet::open(Some(path(&dir)), key.clone());
        assert_eq!(set.mark("item-1", "/usr/bin/git"), Mark::None);
        set.set("item-1", "/usr/bin/git", Mark::Confirmed);
        set.set("item-1", "/usr/bin/evil-tool", Mark::Denied);

        let again = ConfirmSet::open(Some(path(&dir)), key.clone());
        assert_eq!(again.mark("item-1", "/usr/bin/git"), Mark::Confirmed);
        assert_eq!(again.mark("item-1", "/usr/bin/evil-tool"), Mark::Denied);
        assert_eq!(again.mark("item-2", "/usr/bin/git"), Mark::None, "a mark is per item");
        assert_eq!(again.mark("item-1", "/usr/bin/gi"), Mark::None);

        let mut again = again;
        again.set("item-1", "/usr/bin/evil-tool", Mark::Confirmed);
        again.set("item-1", "/usr/bin/git", Mark::None);
        let third = ConfirmSet::open(Some(path(&dir)), key);
        assert_eq!(third.mark("item-1", "/usr/bin/evil-tool"), Mark::Confirmed, "a new mark replaces the old");
        assert_eq!(third.mark("item-1", "/usr/bin/git"), Mark::None);
    }

    #[test]
    fn the_file_reveals_neither_items_nor_executables() {
        let dir = tempfile::tempdir().unwrap();
        let key = SymmetricKey::generate();
        let mut set = ConfirmSet::open(Some(path(&dir)), key.clone());
        set.set("item-7f3a-unique", "/usr/bin/git-unique", Mark::Confirmed);
        let text = std::fs::read_to_string(path(&dir)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["format"], 2);
        assert!(v["set"].as_str().unwrap().starts_with("2."), "one EncString: {text}");
        for needle in ["item-7f3a-unique", "git-unique", "confirmed", "denied"] {
            assert!(!text.contains(needle), "{needle} leaked: {text}");
        }
        // The tag is the documented HMAC, so other tools can compute it.
        let tag = hex::encode(crate::bw::crypto::acl_confirm_tag(&key, "item-7f3a-unique", "/usr/bin/git-unique"));
        let plain = key.decrypt(v["set"].as_str().unwrap()).unwrap();
        assert!(String::from_utf8(plain.to_vec()).unwrap().contains(&tag));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(path(&dir)).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn a_set_under_another_key_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let mut theirs = ConfirmSet::open(Some(path(&dir)), SymmetricKey::generate());
        theirs.set("item-1", "/usr/bin/git", Mark::Confirmed);
        let before = std::fs::read(path(&dir)).unwrap();

        let mut mine = ConfirmSet::open(Some(path(&dir)), SymmetricKey::generate());
        assert_eq!(mine.mark("item-1", "/usr/bin/git"), Mark::None, "unreadable reads as empty");
        mine.set("item-1", "/usr/bin/ssh", Mark::Confirmed);
        assert_eq!(mine.mark("item-1", "/usr/bin/ssh"), Mark::Confirmed, "kept in memory");
        assert_eq!(std::fs::read(path(&dir)).unwrap(), before, "the unreadable file is left alone");
    }

    #[test]
    fn a_corrupt_file_is_set_aside_and_a_fresh_one_written() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(path(&dir).parent().unwrap()).unwrap();
        std::fs::write(path(&dir), b"not json").unwrap();
        let key = SymmetricKey::generate();
        let mut set = ConfirmSet::open(Some(path(&dir)), key.clone());
        assert_eq!(set.mark("i", "/x"), Mark::None);
        set.set("i", "/x", Mark::Denied);
        assert_eq!(std::fs::read(path(&dir).with_file_name("acl-confirmed.corrupt")).unwrap(), b"not json");
        assert_eq!(ConfirmSet::open(Some(path(&dir)), key).mark("i", "/x"), Mark::Denied);
    }

    #[test]
    fn a_memory_only_set_still_remembers() {
        let mut set = ConfirmSet::open(None, SymmetricKey::generate());
        set.set("i", "/x", Mark::Confirmed);
        assert_eq!(set.mark("i", "/x"), Mark::Confirmed);
    }
}
