//! The collection registry: a mergeable record of collections, kept in one
//! secure note so that an empty collection survives and devices can merge.

// Task 10 wires the registry into the Bitwarden backend.
#![allow(dead_code)]

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The `bwss:id` of the registry note.
pub const REGISTRY_ID: &str = "_collections";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub label: String,
    pub created: u64,
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Registry(pub BTreeMap<String, Entry>);

impl Registry {
    /// Reads the registry note; bad JSON gives an empty registry.
    pub fn parse(notes: &str) -> Registry {
        match serde_json::from_str(notes) {
            Ok(map) => Registry(map),
            Err(err) => {
                // Never log the note itself.
                tracing::warn!("collection registry is not valid JSON: {err}");
                Registry::default()
            }
        }
    }

    /// Deterministic JSON, so equal registries give equal notes.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.0).expect("a string-keyed map always serializes")
    }

    /// Per id, the newer `created` wins; on a tie a tombstone wins, then the
    /// lower label, so merging is commutative.
    pub fn merge(&mut self, other: &Registry) {
        for (id, theirs) in &other.0 {
            match self.0.get(id) {
                Some(mine) if rank(mine, theirs) != Ordering::Less => {}
                _ => {
                    self.0.insert(id.clone(), theirs.clone());
                }
            }
        }
    }

    /// Sets an entry unconditionally; the caller decides.
    pub fn put(&mut self, id: &str, entry: Entry) {
        self.0.insert(id.to_string(), entry);
    }

    pub fn live(&self) -> impl Iterator<Item = (&String, &Entry)> {
        self.0.iter().filter(|(_, e)| !e.deleted)
    }
}

/// `Greater` when `a` should win over `b`.
fn rank(a: &Entry, b: &Entry) -> Ordering {
    a.created.cmp(&b.created).then(a.deleted.cmp(&b.deleted)).then(b.label.cmp(&a.label))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(label: &str, created: u64, deleted: bool) -> Entry {
        Entry { label: label.into(), created, deleted }
    }

    fn reg(items: &[(&str, Entry)]) -> Registry {
        let mut r = Registry::default();
        for (id, e) in items {
            r.put(id, e.clone());
        }
        r
    }

    #[test]
    fn merge_is_a_union() {
        let a = reg(&[("work", entry("Work", 1, false))]);
        let b = reg(&[("home", entry("Home", 2, false))]);
        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        assert_eq!(ab, ba);
        assert_eq!(ab.0.len(), 2);
        assert!(ab.0.contains_key("work") && ab.0.contains_key("home"));
    }

    #[test]
    fn deletion_survives_merge_until_recreated() {
        let live = reg(&[("work", entry("Work", 5, false))]);
        let tomb = reg(&[("work", entry("Work", 5, true))]);
        let mut m = live.clone();
        m.merge(&tomb);
        assert!(m.0["work"].deleted);
        let mut m2 = tomb.clone();
        m2.merge(&live);
        assert!(m2.0["work"].deleted);
        assert_eq!(m2.live().count(), 0);

        let recreated = reg(&[("work", entry("Work", 9, false))]);
        m.merge(&recreated);
        assert!(!m.0["work"].deleted);
        assert_eq!(m.0["work"].created, 9);
    }

    #[test]
    fn conflicting_entries_merge_commutatively() {
        let a = reg(&[("x", entry("Alpha", 3, false))]);
        let b = reg(&[("x", entry("Beta", 3, false))]);
        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        assert_eq!(ab, ba);
        assert_eq!(ab.0["x"].label, "Alpha");
    }

    #[test]
    fn bad_json_is_empty() {
        assert_eq!(Registry::parse("not json"), Registry::default());
        assert_eq!(Registry::parse(""), Registry::default());
    }

    #[test]
    fn extra_keys_are_ignored_and_deleted_defaults_false() {
        let r = Registry::parse(r#"{"a":{"label":"A","created":1,"extra":true}}"#);
        assert_eq!(r.0["a"], entry("A", 1, false));
    }

    #[test]
    fn to_json_is_deterministic_and_round_trips() {
        let a = reg(&[("b", entry("B", 2, false)), ("a", entry("A", 1, true))]);
        let b = reg(&[("a", entry("A", 1, true)), ("b", entry("B", 2, false))]);
        assert_eq!(a.to_json(), b.to_json());
        assert_eq!(Registry::parse(&a.to_json()), a);
    }

    #[test]
    fn live_skips_deleted() {
        let r = reg(&[("a", entry("A", 1, true)), ("b", entry("B", 1, false))]);
        let ids: Vec<_> = r.live().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["b"]);
    }
}
