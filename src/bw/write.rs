//! Write path: re-apply bwss's own changes to a cipher as the server last
//! returned it, and build new items.
//!
//! bwss changes only its own fields and the value source of the item it read
//! (design §5). Everything else in the cipher passes through untouched.

#![allow(dead_code)] // consumed by the backend in a later task; remove then.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::crypto::{CryptoError, SymmetricKey};
use super::fields::{
    A_ID, A_NAME, A_URI, A_USERNAME, F_ACL, F_ATTR, F_COLLECTION, F_CONTENT_TYPE, F_CREATED, F_ENCODING, F_ID,
    F_LOCATION, F_PASSWORD, field_names, first_index,
};
use super::items::{MAX_NOTES_ENC, MAX_PASSWORD_ENC, RESPONSE_ONLY, format_date, item_key};
use super::scan::{Keys, Scan, ValueSource, normalize_collection, scan};
use crate::model::{ItemData, LOGIN_COLLECTION};

/// Bitwarden's limit on the encrypted size of a custom field value.
const MAX_FIELD_ENC: usize = 5_000;
const TYPE_SECURE_NOTE: u64 = 2;
const FIELD_TEXT: u64 = 0;
const FIELD_HIDDEN: u64 = 1;
/// `passwordHistory` keeps at most this many entries, newest first.
const HISTORY_MAX: usize = 5;

/// bwss's own changes to one item, kept so they can be re-applied to a fresh
/// copy when the server rejects a write as out of date.
#[derive(Clone, Serialize, Deserialize)]
pub struct Patch {
    /// `bwss:id` the patch was built for.
    pub id: String,
    pub base_revision: String,
    /// `(field, plaintext value, hidden)`.
    pub set: Vec<(String, String, bool)>,
    /// Field names; `bwss:attr:` removes every attribute field.
    pub remove: Vec<String>,
    /// ACL lines, merged as a union.
    pub acl_add: Vec<String>,
    pub value: ValueChange,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum ValueChange {
    Keep,
    Set { source: ValueSource, secret: Vec<u8>, base_mark: [u8; 32] },
}

#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("secret is too large for a Bitwarden item")]
    TooLarge,
    #[error("secret does not fit its field and the notes hold the user's text")]
    NotesTaken,
    #[error("the secret was changed elsewhere")]
    Conflict,
    #[error("the item was deleted elsewhere")]
    Gone,
    #[error("the item no longer carries its bwss:id")]
    Unmarked,
}

/// Custom fields being edited: the raw (encrypted) entries with their
/// decrypted names. Entries bwss does not change are kept byte for byte.
struct Fields<'k> {
    key: &'k SymmetricKey,
    raw: Vec<Value>,
    names: Vec<Option<String>>,
}

impl<'k> Fields<'k> {
    fn read(cipher: &Value, key: &'k SymmetricKey) -> Result<Self, CryptoError> {
        let names = field_names(cipher, key)?;
        let raw = cipher.get("fields").and_then(Value::as_array).cloned().unwrap_or_default();
        Ok(Self { key, raw, names })
    }

    fn empty(key: &'k SymmetricKey) -> Self {
        Self { key, raw: Vec::new(), names: Vec::new() }
    }

    /// Decrypted value of the first field called `name`; `""` for null.
    fn value(&self, name: &str) -> Result<Option<Zeroizing<String>>, CryptoError> {
        let Some(i) = first_index(&self.names, name) else { return Ok(None) };
        match self.raw[i].get("value").and_then(Value::as_str) {
            Some(s) if !s.is_empty() => self.key.decrypt_str(s).map(Some),
            _ => Ok(Some(Zeroizing::new(String::new()))),
        }
    }

    /// Sets the first field called `name` to an already encrypted value,
    /// keeping its kind; appends a field when there is none.
    fn set_enc(&mut self, name: &str, enc: String, hidden: bool) {
        match first_index(&self.names, name) {
            Some(i) => {
                if let Some(f) = self.raw[i].as_object_mut() {
                    f.insert("value".into(), Value::String(enc));
                } else {
                    self.raw[i] = self.new_field(name, enc, hidden);
                }
            }
            None => {
                let field = self.new_field(name, enc, hidden);
                self.raw.push(field);
                self.names.push(Some(name.to_owned()));
            }
        }
    }

    fn set(&mut self, name: &str, value: &str, hidden: bool) {
        let enc = self.key.encrypt_str(value);
        self.set_enc(name, enc, hidden);
    }

    fn new_field(&self, name: &str, enc: String, hidden: bool) -> Value {
        let kind = if hidden { FIELD_HIDDEN } else { FIELD_TEXT };
        json!({ "type": kind, "name": self.key.encrypt_str(name), "value": enc, "linkedId": null })
    }

    fn remove_where(&mut self, keep: impl Fn(&str) -> bool, first_only: bool) {
        let mut removed = false;
        let mut i = 0;
        while i < self.raw.len() {
            let hit = !(first_only && removed) && self.names[i].as_deref().is_some_and(|n| !keep(n));
            if hit {
                self.raw.remove(i);
                self.names.remove(i);
                removed = true;
            } else {
                i += 1;
            }
        }
    }

    fn remove_first(&mut self, name: &str) {
        self.remove_where(|n| n != name, true);
    }

    /// Removes every field called `name`, so no later duplicate takes its
    /// place when bwss removes a field that decides how the value is read.
    fn remove_all(&mut self, name: &str) {
        self.remove_where(|n| n != name, false);
    }

    fn remove_prefix(&mut self, prefix: &str) {
        self.remove_where(|n| !n.starts_with(prefix), false);
    }
}

fn now_rfc3339() -> String {
    format_date(crate::model::now())
}

/// Stores `stored` (text, or base64 of binary) where bwss owns the storage:
/// the `bwss:password` field, or the notes when it is too large for a field
/// and the notes are empty or already bwss's (design §5.2).
fn write_owned_field(body: &mut Map<String, Value>, fields: &mut Fields, stored: &str) -> Result<(), WriteError> {
    let enc = fields.key.encrypt_str(stored);
    if enc.len() <= MAX_FIELD_ENC {
        fields.set_enc(F_PASSWORD, enc, true);
        return Ok(());
    }
    if enc.len() > MAX_NOTES_ENC {
        return Err(WriteError::TooLarge);
    }
    let bwss_notes = fields.value(F_LOCATION)?.is_some_and(|l| l.as_str() == "notes");
    let notes_empty = match body.get("notes").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => fields.key.decrypt_str(s)?.is_empty(),
        _ => true,
    };
    if !bwss_notes && !notes_empty {
        return Err(WriteError::NotesTaken);
    }
    body.insert("notes".into(), Value::String(enc));
    fields.set(F_LOCATION, "notes", false);
    fields.remove_all(F_PASSWORD);
    Ok(())
}

fn write_notes(body: &mut Map<String, Value>, key: &SymmetricKey, text: &str) -> Result<(), WriteError> {
    let value = if text.is_empty() { Value::Null } else { Value::String(key.encrypt_str(text)) };
    if value.as_str().map_or(0, str::len) > MAX_NOTES_ENC {
        return Err(WriteError::TooLarge);
    }
    body.insert("notes".into(), value);
    Ok(())
}

/// Writes a login password the way the official clients do: the old one
/// goes first into the history (at most 5) and the revision date is set.
fn write_login_password(body: &mut Map<String, Value>, key: &SymmetricKey, text: &str) -> Result<(), WriteError> {
    let enc = if text.is_empty() { None } else { Some(key.encrypt_str(text)) };
    if enc.as_ref().map_or(0, String::len) > MAX_PASSWORD_ENC {
        return Err(WriteError::TooLarge);
    }
    let existing = body.get("login").and_then(Value::as_object).cloned();
    let had_login = existing.is_some();
    let mut login = existing.unwrap_or_default();
    let old = login.get("password").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned);
    match &old {
        Some(o) if key.decrypt_str(o)?.as_str() == text => return Ok(()),
        None if text.is_empty() => return Ok(()),
        _ => {}
    }
    if let Some(old) = old {
        let mut history = body.get("passwordHistory").and_then(Value::as_array).cloned().unwrap_or_default();
        history.insert(0, json!({ "password": old, "lastUsedDate": now_rfc3339() }));
        history.truncate(HISTORY_MAX);
        body.insert("passwordHistory".into(), Value::Array(history));
    }
    login.insert("password".into(), enc.map_or(Value::Null, Value::String));
    login.insert("passwordRevisionDate".into(), Value::String(now_rfc3339()));
    if !had_login {
        for k in ["username", "uris", "totp"] {
            login.entry(k).or_insert(Value::Null);
        }
    }
    body.insert("login".into(), Value::Object(login));
    Ok(())
}

/// Writes `secret` back to `source` (design §5.2, ADR 0005).
fn write_value(
    body: &mut Map<String, Value>,
    fields: &mut Fields,
    source: ValueSource,
    secret: &[u8],
) -> Result<(), WriteError> {
    let key = fields.key;
    if let Ok(text) = std::str::from_utf8(secret) {
        fields.remove_all(F_ENCODING);
        return match source {
            ValueSource::Field => write_owned_field(body, fields, text),
            ValueSource::BwssNotes | ValueSource::NoteBody => write_notes(body, key, text),
            ValueSource::LoginPassword => write_login_password(body, key, text),
        };
    }
    // Binary: only into storage bwss owns. A login password or a note's own
    // text is never touched; a new bwss:password becomes the source instead.
    let b64 = Zeroizing::new(B64.encode(secret));
    match source {
        ValueSource::BwssNotes => write_notes(body, key, &b64)?,
        ValueSource::Field | ValueSource::LoginPassword | ValueSource::NoteBody => {
            write_owned_field(body, fields, &b64)?;
        }
    }
    fields.set(F_ENCODING, "base64", false);
    Ok(())
}

/// Applies `patch` to `cipher` (the server's copy, fresh or as last read)
/// and returns the body of the update request.
pub fn apply(cipher: &Value, patch: &Patch, keys: &Keys) -> Result<Map<String, Value>, WriteError> {
    // 1. Abort checks against the copy being written over.
    if cipher.get("deletedDate").is_some_and(|d| !d.is_null()) {
        return Err(WriteError::Gone);
    }
    let fresh = match scan(cipher, keys) {
        Scan::Marked(m) if m.item.id == patch.id => m,
        _ => return Err(WriteError::Unmarked),
    };
    if let ValueChange::Set { source, base_mark, .. } = &patch.value
        && (fresh.source != *source || fresh.mark != *base_mark)
    {
        return Err(WriteError::Conflict);
    }
    let Some(object) = cipher.as_object() else { return Err(WriteError::Unmarked) };

    // 2. Start from the cipher as returned, minus response-only metadata.
    let mut body: Map<String, Value> = object
        .iter()
        .filter(|(k, _)| !RESPONSE_ONLY.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let key = item_key(cipher, &keys.user)?;
    let mut fields = Fields::read(cipher, &key)?;

    // 3. The value goes back to its source.
    if let ValueChange::Set { secret, .. } = &patch.value {
        write_value(&mut body, &mut fields, fresh.source, secret)?;
    }

    // 4. bwss's own fields.
    for name in &patch.remove {
        if name == F_ATTR {
            fields.remove_prefix(F_ATTR);
        } else {
            fields.remove_first(name);
        }
    }
    for (name, value, hidden) in &patch.set {
        fields.set(name, value, *hidden);
    }

    // 5. The ACL is the union of the server's lines and bwss's.
    if !patch.acl_add.is_empty() {
        let current = fields.value(F_ACL)?;
        let mut lines: Vec<String> = current
            .as_deref()
            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).map(str::to_owned).collect())
            .unwrap_or_default();
        let before = lines.len();
        for line in &patch.acl_add {
            if !line.trim().is_empty() && !lines.contains(line) {
                lines.push(line.clone());
            }
        }
        if lines.len() != before || current.is_none() {
            fields.set(F_ACL, &lines.join("\n"), true);
        }
    }

    // 6. Everything new was encrypted under the item key above.
    body.insert("fields".into(), Value::Array(fields.raw));
    if !body.get("passwordHistory").is_some_and(Value::is_array) {
        body.insert("passwordHistory".into(), json!([]));
    }
    let revision = cipher.get("revisionDate").and_then(Value::as_str).unwrap_or(&patch.base_revision);
    body.insert("lastKnownRevisionDate".into(), json!(revision));
    Ok(body)
}

/// Body of the create request for a new item: a personal secure note with
/// empty notes and the secret in `bwss:password` (design §5.1).
pub fn new_note(item: &ItemData, folder_id: Option<&str>, keys: &Keys) -> Result<Map<String, Value>, WriteError> {
    let key = &keys.user;
    let mut body = Map::new();
    let mut fields = Fields::empty(key);
    fields.set(F_ID, &item.id, false);
    write_value(&mut body, &mut fields, ValueSource::Field, &item.secret)?;
    for (name, value) in &item.attributes {
        if [A_ID, A_NAME, A_USERNAME, A_URI].contains(&name.as_str()) {
            continue;
        }
        fields.set(&format!("{F_ATTR}{name}"), value, false);
    }
    if normalize_collection(&item.collection) != LOGIN_COLLECTION {
        fields.set(F_COLLECTION, &item.collection, false);
    }
    if item.content_type != "text/plain" {
        fields.set(F_CONTENT_TYPE, &item.content_type, false);
    }
    if !item.acl.is_empty() {
        fields.set(F_ACL, &item.acl.join("\n"), true);
    }
    fields.set(F_CREATED, &item.created.to_string(), false);

    body.entry("notes").or_insert(Value::Null);
    body.insert("type".into(), json!(TYPE_SECURE_NOTE));
    body.insert("organizationId".into(), Value::Null);
    body.insert("folderId".into(), folder_id.map_or(Value::Null, |f| json!(f)));
    body.insert("name".into(), json!(key.encrypt_str(&item.label)));
    body.insert("login".into(), Value::Null);
    body.insert("secureNote".into(), json!({ "type": 0 }));
    body.insert("favorite".into(), json!(false));
    body.insert("reprompt".into(), json!(0));
    body.insert("key".into(), Value::Null);
    body.insert("passwordHistory".into(), json!([]));
    body.insert("fields".into(), Value::Array(fields.raw));
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bw::scan::MarkedItem;
    use crate::model::Attributes;

    fn keys() -> Keys {
        Keys { user: SymmetricKey::generate(), mark: SymmetricKey::generate() }
    }

    /// `(name, value, hidden)`.
    type F<'a> = (&'a str, &'a str, bool);

    fn enc_fields(key: &SymmetricKey, fields: &[F]) -> Value {
        Value::Array(
            fields
                .iter()
                .map(|(n, v, h)| {
                    json!({ "type": u64::from(*h), "name": key.encrypt_str(n), "value": key.encrypt_str(v), "linkedId": null })
                })
                .collect(),
        )
    }

    fn history(key: &SymmetricKey, n: usize) -> Value {
        Value::Array(
            (0..n)
                .map(|i| json!({ "password": key.encrypt_str(&format!("h{i}")), "lastUsedDate": "2025-01-01T00:00:00Z" }))
                .collect(),
        )
    }

    fn login(k: &Keys, fields: &[F], password: Option<&str>, notes: Option<&str>) -> Value {
        json!({
            "id": "c1", "object": "cipherDetails", "type": 1, "organizationId": null, "folderId": "f1",
            "revisionDate": "2026-01-02T03:04:05Z", "creationDate": "2025-01-02T03:04:05Z", "deletedDate": null,
            "edit": true, "viewPassword": true, "permissions": { "delete": true, "restore": true },
            "collectionIds": [], "attachments": null, "organizationUseTotp": false, "data": { "x": 1 },
            "favorite": false, "reprompt": 0, "key": null, "archivedDate": "2026-02-02T00:00:00Z",
            "name": k.user.encrypt_str("GitHub"),
            "notes": notes.map(|n| k.user.encrypt_str(n)),
            "login": {
                "username": k.user.encrypt_str("me"),
                "password": password.map(|p| k.user.encrypt_str(p)),
                "passwordRevisionDate": "2025-06-01T00:00:00Z",
                "totp": null,
                "uris": [{ "uri": k.user.encrypt_str("https://github.com"), "match": null }],
            },
            "passwordHistory": history(&k.user, 2),
            "fields": enc_fields(&k.user, fields),
        })
    }

    fn note(k: &Keys, fields: &[F], notes: Option<&str>) -> Value {
        json!({
            "id": "n1", "type": 2, "organizationId": null, "folderId": "f1",
            "revisionDate": "2026-01-02T03:04:05Z", "creationDate": "2025-01-02T03:04:05Z",
            "name": k.user.encrypt_str("Note"),
            "notes": notes.map(|n| k.user.encrypt_str(n)),
            "secureNote": { "type": 0 },
            "passwordHistory": null,
            "fields": enc_fields(&k.user, fields),
        })
    }

    fn marked(c: &Value, k: &Keys) -> Box<MarkedItem> {
        match scan(c, k) {
            Scan::Marked(m) => m,
            other => panic!("expected Marked, got {other:?}"),
        }
    }

    fn keep(c: &Value, k: &Keys) -> Patch {
        let m = marked(c, k);
        Patch {
            id: m.item.id.clone(),
            base_revision: m.revision_date.clone(),
            set: Vec::new(),
            remove: Vec::new(),
            acl_add: Vec::new(),
            value: ValueChange::Keep,
        }
    }

    fn set_secret(c: &Value, k: &Keys, secret: &[u8]) -> Patch {
        let m = marked(c, k);
        Patch { value: ValueChange::Set { source: m.source, secret: secret.to_vec(), base_mark: m.mark }, ..keep(c, k) }
    }

    fn dec_with(key: &SymmetricKey, v: &Value) -> String {
        key.decrypt_str(v.as_str().expect("an encrypted string")).unwrap().to_string()
    }

    /// The server's copy after a write: the body plus response-only metadata.
    fn as_server(body: &Map<String, Value>) -> Value {
        let mut b = body.clone();
        b.remove("lastKnownRevisionDate");
        b.insert("id".into(), json!("c1"));
        b.insert("revisionDate".into(), json!("2026-03-03T00:00:00Z"));
        Value::Object(b)
    }

    /// Decrypted names of every field, in order.
    fn names(body: &Map<String, Value>, key: &SymmetricKey) -> Vec<String> {
        body["fields"].as_array().unwrap().iter().map(|f| dec_with(key, &f["name"])).collect()
    }

    /// Decrypted value and type of the first field called `name`.
    fn field(body: &Map<String, Value>, key: &SymmetricKey, name: &str) -> Option<(String, u64)> {
        body["fields"].as_array().unwrap().iter().find(|f| dec_with(key, &f["name"]) == name).map(|f| {
            let v = if f["value"].is_null() { String::new() } else { dec_with(key, &f["value"]) };
            (v, f["type"].as_u64().unwrap())
        })
    }

    /// Every top-level key of `c` except `fields` and the response-only ones
    /// is unchanged in `body`, and `body` has no key `c` lacks (except
    /// `lastKnownRevisionDate`).
    fn assert_rest_unchanged(c: &Value, body: &Map<String, Value>, except: &[&str]) {
        for (k, v) in c.as_object().unwrap() {
            if RESPONSE_ONLY.contains(&k.as_str()) || except.contains(&k.as_str()) {
                continue;
            }
            assert_eq!(body.get(k), Some(v), "key {k} changed");
        }
        for k in body.keys() {
            assert!(c.get(k).is_some() || k == "lastKnownRevisionDate" || except.contains(&k.as_str()), "new key {k}");
        }
    }

    #[test]
    fn write_back_to_login_password_keeps_history() {
        let k = keys();
        let mut c = login(&k, &[("bwss:id", "x", false)], Some("old"), None);
        c["passwordHistory"] = history(&k.user, 5);
        let body = apply(&c, &set_secret(&c, &k, b"new"), &k).unwrap();
        assert_eq!(dec_with(&k.user, &body["login"]["password"]), "new");
        let h = body["passwordHistory"].as_array().unwrap();
        assert_eq!(h.len(), 5);
        assert_eq!(dec_with(&k.user, &h[0]["password"]), "old");
        assert_eq!(h[0]["password"], c["login"]["password"]);
        assert!(h[0]["lastUsedDate"].as_str().unwrap().contains('T'));
        // the oldest entry fell off
        assert_eq!(h[1..], c["passwordHistory"].as_array().unwrap()[..4]);
        let rev = body["login"]["passwordRevisionDate"].as_str().unwrap();
        assert_ne!(rev, "2025-06-01T00:00:00Z");
        assert_eq!(body["login"]["username"], c["login"]["username"]);
        assert_eq!(body["login"]["uris"], c["login"]["uris"]);
        assert_eq!(body["fields"], c["fields"]);
        assert_eq!(body["lastKnownRevisionDate"], json!("2026-01-02T03:04:05Z"));
        assert_rest_unchanged(&c, &body, &["login", "passwordHistory"]);
    }

    #[test]
    fn write_back_to_null_login_password() {
        let k = keys();
        let mut c = login(&k, &[("bwss:id", "x", false)], None, None);
        c["passwordHistory"] = Value::Null;
        c["login"] = Value::Null;
        let body = apply(&c, &set_secret(&c, &k, b"new"), &k).unwrap();
        assert_eq!(dec_with(&k.user, &body["login"]["password"]), "new");
        assert_eq!(body["passwordHistory"], json!([]));

        let mut c = login(&k, &[("bwss:id", "x", false)], None, None);
        c["passwordHistory"] = Value::Null;
        c["login"] = json!({ "password": null });
        let body = apply(&c, &set_secret(&c, &k, b"new"), &k).unwrap();
        assert_eq!(dec_with(&k.user, &body["login"]["password"]), "new");
        assert_eq!(body["passwordHistory"], json!([]));
        assert!(body["login"]["passwordRevisionDate"].is_string());
    }

    #[test]
    fn write_back_to_field_and_notes_leaves_the_rest() {
        let k = keys();
        let fields = [
            ("bwss:id", "x", false),
            ("obsidian:id", "o", false),
            ("bwss:password", "old", true),
            ("dybw:x", "d", false),
            ("plain", "p", false),
        ];
        let c = login(&k, &fields, Some("pw"), Some("user notes"));
        let body = apply(&c, &set_secret(&c, &k, b"new"), &k).unwrap();
        assert_eq!(field(&body, &k.user, "bwss:password"), Some(("new".into(), 1)));
        let (before, after) = (c["fields"].as_array().unwrap(), body["fields"].as_array().unwrap());
        assert_eq!(after.len(), before.len());
        for i in [0, 1, 3, 4] {
            assert_eq!(after[i], before[i], "field {i} changed");
        }
        // login.password, notes, history, name, uris, folderId, archivedDate unchanged
        assert_rest_unchanged(&c, &body, &["fields"]);
        assert_eq!(marked(&as_server(&body), &k).item.secret.as_slice(), b"new");

        // NoteBody source: notes change, fields unchanged
        let c = note(&k, &[("bwss:id", "x", false), ("obsidian:id", "o", false)], Some("body"));
        let body = apply(&c, &set_secret(&c, &k, b"new"), &k).unwrap();
        assert_eq!(dec_with(&k.user, &body["notes"]), "new");
        assert_eq!(body["fields"], c["fields"]);
        assert_rest_unchanged(&c, &body, &["notes", "passwordHistory"]);
        assert_eq!(body["passwordHistory"], json!([]));

        // BwssNotes source: notes change, fields unchanged
        let c = login(&k, &[("bwss:id", "x", false), ("bwss:location", "notes", false)], Some("pw"), Some("big"));
        let body = apply(&c, &set_secret(&c, &k, b"new"), &k).unwrap();
        assert_eq!(dec_with(&k.user, &body["notes"]), "new");
        assert_eq!(body["fields"], c["fields"]);
        assert_rest_unchanged(&c, &body, &["notes"]);
    }

    #[test]
    fn patch_changes_only_the_first_duplicate() {
        let k = keys();
        let c = login(
            &k,
            &[("bwss:id", "x", false), ("bwss:password", "1", true), ("bwss:password", "2", true)],
            None,
            None,
        );
        let body = apply(&c, &set_secret(&c, &k, b"new"), &k).unwrap();
        let after = body["fields"].as_array().unwrap();
        assert_eq!(dec_with(&k.user, &after[1]["value"]), "new");
        assert_eq!(after[2], c["fields"][2]);

        // set and remove act on the first match too
        let c = login(
            &k,
            &[
                ("bwss:id", "x", false),
                ("bwss:label", "L1", false),
                ("bwss:label", "L2", false),
                ("bwss:content-type", "a", false),
                ("bwss:content-type", "b", false),
            ],
            Some("pw"),
            None,
        );
        let mut p = keep(&c, &k);
        p.set = vec![("bwss:label".into(), "New".into(), false)];
        p.remove = vec!["bwss:content-type".into()];
        let body = apply(&c, &p, &k).unwrap();
        assert_eq!(names(&body, &k.user), ["bwss:id", "bwss:label", "bwss:label", "bwss:content-type"]);
        let after = body["fields"].as_array().unwrap();
        assert_eq!(dec_with(&k.user, &after[1]["value"]), "New");
        assert_eq!(after[2], c["fields"][2]);
        assert_eq!(after[3], c["fields"][4]);
    }

    #[test]
    fn set_and_remove_replace_the_attribute_set() {
        let k = keys();
        let c = login(
            &k,
            &[
                ("bwss:id", "x", false),
                ("bwss:attr:a", "1", false),
                ("obsidian:id", "o", false),
                ("bwss:attr:b", "2", false),
            ],
            Some("pw"),
            None,
        );
        let mut p = keep(&c, &k);
        p.remove = vec!["bwss:attr:".into()];
        p.set = vec![("bwss:attr:c".into(), "3".into(), false), ("bwss:acl".into(), "/x".into(), true)];
        let body = apply(&c, &p, &k).unwrap();
        assert_eq!(names(&body, &k.user), ["bwss:id", "obsidian:id", "bwss:attr:c", "bwss:acl"]);
        assert_eq!(field(&body, &k.user, "bwss:attr:c"), Some(("3".into(), 0)));
        assert_eq!(field(&body, &k.user, "bwss:acl"), Some(("/x".into(), 1)));
        assert_eq!(body["fields"][1], c["fields"][2]);
        assert_rest_unchanged(&c, &body, &["fields"]);
    }

    #[test]
    fn response_only_keys_are_stripped_and_history_always_sent() {
        let k = keys();
        let item_key = SymmetricKey::generate();
        let mut c = note(&k, &[], Some("body"));
        c["key"] = json!(k.user.encrypt(&item_key.to_bytes()));
        c["fields"] = enc_fields(&item_key, &[("bwss:id", "x", false), ("bwss:password", "old", true)]);
        c["notes"] = json!(item_key.encrypt_str("body"));
        c["name"] = json!(item_key.encrypt_str("Note"));
        c["passwordHistory"] = Value::Null;
        for key in RESPONSE_ONLY {
            c.as_object_mut().unwrap().entry(*key).or_insert(json!("present"));
        }
        c["deletedDate"] = Value::Null;
        let mut p = set_secret(&c, &k, b"new");
        p.set = vec![("bwss:attr:a".into(), "1".into(), false)];
        p.acl_add = vec!["/bin/x".into()];
        let body = apply(&c, &p, &k).unwrap();
        for key in RESPONSE_ONLY {
            assert!(!body.contains_key(*key), "{key} was sent");
        }
        assert_eq!(body["passwordHistory"], json!([]));
        assert_eq!(body["lastKnownRevisionDate"], json!("2026-01-02T03:04:05Z"));
        assert_eq!(body["key"], c["key"]);
        assert_eq!(field(&body, &item_key, "bwss:password"), Some(("new".into(), 1)));
        assert_eq!(field(&body, &item_key, "bwss:attr:a"), Some(("1".into(), 0)));
        assert_eq!(field(&body, &item_key, "bwss:acl"), Some(("/bin/x".into(), 1)));
        assert_eq!(dec_with(&item_key, &body["notes"]), "body");
        assert_eq!(marked(&as_server(&body), &k).item.secret.as_slice(), b"new");
    }

    #[test]
    fn oversize_field_value_moves_to_empty_notes_or_fails() {
        let k = keys();
        let big = vec![b'x'; 4_000];
        let c = login(&k, &[("bwss:id", "x", false), ("bwss:password", "old", true)], Some("pw"), None);
        let body = apply(&c, &set_secret(&c, &k, &big), &k).unwrap();
        assert_eq!(dec_with(&k.user, &body["notes"]).as_bytes(), big.as_slice());
        assert_eq!(field(&body, &k.user, "bwss:location"), Some(("notes".into(), 0)));
        assert_eq!(field(&body, &k.user, "bwss:password"), None);
        assert_eq!(body["login"], c["login"]);
        let m = marked(&as_server(&body), &k);
        assert_eq!((m.source, m.item.secret.as_slice()), (ValueSource::BwssNotes, big.as_slice()));

        // the notes already hold bwss's secret: they are reused
        let c = login(
            &k,
            &[("bwss:id", "x", false), ("bwss:password", "old", true), ("bwss:location", "notes", false)],
            None,
            Some("old big"),
        );
        let body = apply(&c, &set_secret(&c, &k, &big), &k).unwrap();
        assert_eq!(dec_with(&k.user, &body["notes"]).as_bytes(), big.as_slice());
        assert_eq!(names(&body, &k.user), ["bwss:id", "bwss:location"]);

        let c = login(&k, &[("bwss:id", "x", false), ("bwss:password", "old", true)], Some("pw"), Some("mine"));
        assert!(matches!(apply(&c, &set_secret(&c, &k, &big), &k), Err(WriteError::NotesTaken)));

        let c = login(&k, &[("bwss:id", "x", false), ("bwss:password", "old", true)], Some("pw"), None);
        assert!(matches!(apply(&c, &set_secret(&c, &k, &[b'x'; 8_000]), &k), Err(WriteError::TooLarge)));

        let c = login(&k, &[("bwss:id", "x", false)], Some("pw"), None);
        assert!(matches!(apply(&c, &set_secret(&c, &k, &big), &k), Err(WriteError::TooLarge)));

        let c = note(&k, &[("bwss:id", "x", false)], Some("body"));
        assert!(matches!(apply(&c, &set_secret(&c, &k, &[b'x'; 8_000]), &k), Err(WriteError::TooLarge)));
    }

    #[test]
    fn binary_secrets_only_go_into_bwss_storage() {
        let k = keys();
        let bin = [0xff_u8, 0];

        // Field source: base64 in bwss:password; then text removes the encoding
        let c = login(&k, &[("bwss:id", "x", false), ("bwss:password", "old", true)], Some("pw"), None);
        let body = apply(&c, &set_secret(&c, &k, &bin), &k).unwrap();
        assert_eq!(field(&body, &k.user, "bwss:password"), Some(("/wA=".into(), 1)));
        assert_eq!(field(&body, &k.user, "bwss:encoding"), Some(("base64".into(), 0)));
        assert_eq!(body["login"], c["login"]);
        let c = as_server(&body);
        assert_eq!(marked(&c, &k).item.secret.as_slice(), &bin);
        let body = apply(&c, &set_secret(&c, &k, b"text"), &k).unwrap();
        assert_eq!(field(&body, &k.user, "bwss:password"), Some(("text".into(), 1)));
        assert_eq!(field(&body, &k.user, "bwss:encoding"), None);
        assert_eq!(marked(&as_server(&body), &k).item.secret.as_slice(), b"text");

        // BwssNotes source: base64 in the notes
        let c = login(&k, &[("bwss:id", "x", false), ("bwss:location", "notes", false)], None, Some("big"));
        let body = apply(&c, &set_secret(&c, &k, &bin), &k).unwrap();
        assert_eq!(dec_with(&k.user, &body["notes"]), "/wA=");
        assert_eq!(field(&body, &k.user, "bwss:encoding"), Some(("base64".into(), 0)));
        assert_eq!(field(&body, &k.user, "bwss:password"), None);
        let m = marked(&as_server(&body), &k);
        assert_eq!((m.source, m.item.secret.as_slice()), (ValueSource::BwssNotes, &bin[..]));

        // LoginPassword source: a new field holds it, the login is untouched
        let c = login(&k, &[("bwss:id", "x", false), ("obsidian:id", "o", false)], Some("pw"), None);
        let body = apply(&c, &set_secret(&c, &k, &bin), &k).unwrap();
        assert_eq!(body["login"], c["login"]);
        assert_eq!(body["passwordHistory"], c["passwordHistory"]);
        assert_eq!(names(&body, &k.user), ["bwss:id", "obsidian:id", "bwss:password", "bwss:encoding"]);
        assert_eq!(body["fields"].as_array().unwrap()[..2], c["fields"].as_array().unwrap()[..]);
        assert_eq!(field(&body, &k.user, "bwss:password"), Some(("/wA=".into(), 1)));
        assert_eq!(field(&body, &k.user, "bwss:encoding"), Some(("base64".into(), 0)));
        assert_rest_unchanged(&c, &body, &["fields"]);
        let m = marked(&as_server(&body), &k);
        assert_eq!((m.source, m.item.secret.as_slice()), (ValueSource::Field, &bin[..]));

        // NoteBody source: same, the notes are untouched
        let c = note(&k, &[("bwss:id", "x", false)], Some("body"));
        let body = apply(&c, &set_secret(&c, &k, &bin), &k).unwrap();
        assert_eq!(body["notes"], c["notes"]);
        assert_eq!(names(&body, &k.user), ["bwss:id", "bwss:password", "bwss:encoding"]);
        assert_eq!(field(&body, &k.user, "bwss:password"), Some(("/wA=".into(), 1)));
        assert_rest_unchanged(&c, &body, &["fields", "passwordHistory"]);
        let m = marked(&as_server(&body), &k);
        assert_eq!((m.source, m.item.secret.as_slice()), (ValueSource::Field, &bin[..]));

        // NoteBody source, binary too large for a field, user notes present
        let huge = vec![0xff_u8; 4_000];
        assert!(matches!(apply(&c, &set_secret(&c, &k, &huge), &k), Err(WriteError::NotesTaken)));
        // ... and with empty notes it goes to the notes, owned by bwss from then on
        let c = note(&k, &[("bwss:id", "x", false)], None);
        let body = apply(&c, &set_secret(&c, &k, &huge), &k).unwrap();
        assert_eq!(field(&body, &k.user, "bwss:location"), Some(("notes".into(), 0)));
        assert_eq!(field(&body, &k.user, "bwss:password"), None);
        let m = marked(&as_server(&body), &k);
        assert_eq!((m.source, m.item.secret.as_slice()), (ValueSource::BwssNotes, huge.as_slice()));
    }

    #[test]
    fn retry_checks_abort_on_the_fresh_copy() {
        let k = keys();
        let c = login(&k, &[("bwss:id", "x", false), ("obsidian:id", "o", false)], Some("pw"), None);
        let p = set_secret(&c, &k, b"new");

        // value source changed on the server (mark differs)
        let mut fresh = c.clone();
        fresh["login"]["password"] = json!(k.user.encrypt_str("pw"));
        assert!(matches!(apply(&fresh, &p, &k), Err(WriteError::Conflict)));
        // a bwss:password appeared: the source itself changed
        let mut fresh = c.clone();
        fresh["fields"].as_array_mut().unwrap().push(enc_fields(&k.user, &[("bwss:password", "", true)])[0].clone());
        assert!(matches!(apply(&fresh, &p, &k), Err(WriteError::Conflict)));
        // Keep never compares marks
        let mut fresh = c.clone();
        fresh["login"]["password"] = json!(k.user.encrypt_str("other"));
        assert!(apply(&fresh, &keep(&c, &k), &k).is_ok());

        // trashed
        let mut fresh = c.clone();
        fresh["deletedDate"] = json!("2026-05-05T00:00:00Z");
        assert!(matches!(apply(&fresh, &p, &k), Err(WriteError::Gone)));
        assert!(matches!(apply(&fresh, &keep(&c, &k), &k), Err(WriteError::Gone)));

        // bwss:id removed, changed or blanked
        let fresh = login(&k, &[("obsidian:id", "o", false)], Some("pw"), None);
        assert!(matches!(apply(&fresh, &keep(&c, &k), &k), Err(WriteError::Unmarked)));
        let fresh = login(&k, &[("bwss:id", "y", false), ("obsidian:id", "o", false)], Some("pw"), None);
        assert!(matches!(apply(&fresh, &keep(&c, &k), &k), Err(WriteError::Unmarked)));
        let fresh = login(&k, &[("bwss:id", " ", false), ("obsidian:id", "o", false)], Some("pw"), None);
        assert!(matches!(apply(&fresh, &keep(&c, &k), &k), Err(WriteError::Unmarked)));
        // no longer readable as bwss's item
        let mut fresh = c.clone();
        fresh["type"] = json!(3);
        assert!(matches!(apply(&fresh, &keep(&c, &k), &k), Err(WriteError::Unmarked)));

        // only a foreign field changed: the write goes through and keeps it
        let mut fresh = c.clone();
        fresh["fields"][1]["value"] = json!(k.user.encrypt_str("o2"));
        fresh["name"] = json!(k.user.encrypt_str("Renamed"));
        let body = apply(&fresh, &p, &k).unwrap();
        assert_eq!(body["fields"][1], fresh["fields"][1]);
        assert_eq!(body["name"], fresh["name"]);
        assert_eq!(dec_with(&k.user, &body["login"]["password"]), "new");
    }

    #[test]
    fn acl_merges_as_a_union() {
        let k = keys();
        let c = login(&k, &[("bwss:id", "x", false), ("bwss:acl", "a\nb", true)], Some("pw"), None);
        let mut p = keep(&c, &k);
        p.acl_add = vec!["c".into(), "a".into()];
        let body = apply(&c, &p, &k).unwrap();
        assert_eq!(field(&body, &k.user, "bwss:acl"), Some(("a\nb\nc".into(), 1)));

        // nothing new: the field is left as it was
        p.acl_add = vec!["b".into()];
        assert_eq!(apply(&c, &p, &k).unwrap()["fields"], c["fields"]);

        // no ACL yet: a hidden field is added
        let c = login(&k, &[("bwss:id", "x", false)], Some("pw"), None);
        p.acl_add = vec!["/bin/x".into()];
        let body = apply(&c, &p, &k).unwrap();
        assert_eq!(field(&body, &k.user, "bwss:acl"), Some(("/bin/x".into(), 1)));
    }

    fn item(secret: &[u8]) -> ItemData {
        let mut attributes = Attributes::new();
        attributes.insert("service".into(), "github".into());
        attributes.insert("bwss:name".into(), "derived".into());
        ItemData {
            id: "abc123".into(),
            collection: "login".into(),
            label: "GitHub token".into(),
            attributes,
            secret: Zeroizing::new(secret.to_vec()),
            content_type: "text/plain".into(),
            created: 1_700_000_000,
            modified: 0,
            acl: vec!["/usr/bin/git".into()],
        }
    }

    #[test]
    fn new_items_are_personal_secure_notes() {
        let k = keys();
        let body = new_note(&item(b"s"), Some("f1"), &k).unwrap();
        assert_eq!(body["type"], 2);
        assert_eq!(body["notes"], Value::Null);
        assert_eq!(body["login"], Value::Null);
        assert_eq!(body["organizationId"], Value::Null);
        assert_eq!(body["folderId"], "f1");
        assert_eq!(body["secureNote"], json!({ "type": 0 }));
        assert_eq!(body["passwordHistory"], json!([]));
        assert_eq!(dec_with(&k.user, &body["name"]), "GitHub token");
        assert!(!body.contains_key("lastKnownRevisionDate"));
        assert_eq!(
            names(&body, &k.user),
            ["bwss:id", "bwss:password", "bwss:attr:service", "bwss:acl", "bwss:created"]
        );
        assert_eq!(field(&body, &k.user, "bwss:id"), Some(("abc123".into(), 0)));
        assert_eq!(field(&body, &k.user, "bwss:password"), Some(("s".into(), 1)));
        assert_eq!(field(&body, &k.user, "bwss:attr:service"), Some(("github".into(), 0)));
        assert_eq!(field(&body, &k.user, "bwss:acl"), Some(("/usr/bin/git".into(), 1)));
        assert_eq!(field(&body, &k.user, "bwss:created"), Some(("1700000000".into(), 0)));
        let m = marked(&as_server(&body), &k);
        assert_eq!(
            (m.source, m.item.secret.as_slice(), m.item.created),
            (ValueSource::Field, &b"s"[..], 1_700_000_000)
        );

        // no folder; another collection, content type and a binary secret
        let mut it = item(&[0xff, 0]);
        it.collection = "work".into();
        it.content_type = "application/octet-stream".into();
        it.acl.clear();
        let body = new_note(&it, None, &k).unwrap();
        assert_eq!(body["folderId"], Value::Null);
        assert_eq!(
            names(&body, &k.user),
            [
                "bwss:id",
                "bwss:password",
                "bwss:encoding",
                "bwss:attr:service",
                "bwss:collection",
                "bwss:content-type",
                "bwss:created"
            ]
        );
        let m = marked(&as_server(&body), &k);
        assert_eq!((m.item.collection.as_str(), m.item.secret.as_slice()), ("work", &[0xff_u8, 0][..]));
        assert_eq!(m.item.content_type, "application/octet-stream");

        // a 4,000-byte secret goes to the notes
        let big = vec![b'x'; 4_000];
        let body = new_note(&item(&big), None, &k).unwrap();
        assert_eq!(dec_with(&k.user, &body["notes"]).as_bytes(), big.as_slice());
        assert_eq!(field(&body, &k.user, "bwss:location"), Some(("notes".into(), 0)));
        assert_eq!(field(&body, &k.user, "bwss:password"), None);
        let m = marked(&as_server(&body), &k);
        assert_eq!((m.source, m.item.secret.as_slice()), (ValueSource::BwssNotes, big.as_slice()));
        assert!(matches!(new_note(&item(&[b'x'; 8_000]), None, &k), Err(WriteError::TooLarge)));
    }
}
