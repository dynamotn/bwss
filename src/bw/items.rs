//! Mapping between Secret Service items and Bitwarden login items.
//!
//! An item is a Bitwarden *login*: the name is the label, the password holds
//! the secret (masked in every Bitwarden client), and hidden bookkeeping lives
//! in custom fields whose names start with `bwss:`. Fields of other clients are
//! preserved on edit.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::crypto::{CryptoError, SymmetricKey};
use crate::model::ItemData;

pub const PREFIX: &str = "bwss:";
pub const F_ID: &str = "bwss:id";
pub const F_ATTR: &str = "bwss:attr:";
pub const F_CONTENT_TYPE: &str = "bwss:content-type";
pub const F_ENCODING: &str = "bwss:encoding";
pub const F_LOCATION: &str = "bwss:location";
pub const F_ACL: &str = "bwss:acl";
pub const F_CREATED: &str = "bwss:created";

const TYPE_LOGIN: u64 = 1;
const TYPE_SECURE_NOTE: u64 = 2;
const FIELD_TEXT: u64 = 0;
const FIELD_HIDDEN: u64 = 1;
/// Bitwarden's limits on the encrypted size of a password and of notes.
pub(crate) const MAX_PASSWORD_ENC: usize = 5_000;
pub(crate) const MAX_NOTES_ENC: usize = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum MapError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("secret is too large for a Bitwarden item")]
    TooLarge,
}

pub fn parse_date(s: &str) -> u64 {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|t| u64::try_from(t.unix_timestamp()).unwrap_or(0))
        .unwrap_or(0)
}

pub(crate) fn format_date(secs: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(i64::try_from(secs).unwrap_or(i64::MAX))
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_default()
}

/// The key an item's fields are encrypted with: its own key if it has one.
pub fn item_key(cipher: &Value, user_key: &SymmetricKey) -> Result<SymmetricKey, CryptoError> {
    match cipher.get("key").and_then(Value::as_str) {
        Some(k) if !k.is_empty() => user_key.decrypt_key(k),
        _ => Ok(user_key.clone()),
    }
}

fn dec(v: Option<&Value>, key: &SymmetricKey) -> Result<Option<Zeroizing<String>>, CryptoError> {
    match v.and_then(Value::as_str) {
        Some(s) if !s.is_empty() => key.decrypt_str(s).map(Some),
        _ => Ok(None),
    }
}

/// Decrypted custom fields, in order.
fn fields(cipher: &Value, key: &SymmetricKey) -> Result<Vec<(String, Zeroizing<String>)>, CryptoError> {
    let mut out = Vec::new();
    for f in cipher.get("fields").and_then(Value::as_array).into_iter().flatten() {
        let name = dec(f.get("name"), key)?.map(|n| n.to_string()).unwrap_or_default();
        let value = dec(f.get("value"), key)?.unwrap_or_default();
        out.push((name, value));
    }
    Ok(out)
}

/// Response-only properties that must not be echoed back in a write.
pub(crate) const RESPONSE_ONLY: &[&str] = &[
    "id",
    "revisionDate",
    "creationDate",
    "deletedDate",
    "object",
    "edit",
    "viewPassword",
    "permissions",
    "collectionIds",
    "attachments",
    "organizationUseTotp",
    "data",
];

/// Encodes an item as the body of a create (`existing` = None) or update request.
pub fn encode(
    item: &ItemData,
    existing: Option<&Value>,
    user_key: &SymmetricKey,
    folder_id: &str,
) -> Result<Map<String, Value>, MapError> {
    let mut body: Map<String, Value> = match existing {
        Some(Value::Object(o)) => o
            .iter()
            .filter(|(k, _)| !RESPONSE_ONLY.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        _ => Map::new(),
    };
    let key = match existing {
        Some(c) => item_key(c, user_key)?,
        None => user_key.clone(),
    };
    let ty = existing.and_then(|c| c.get("type")).and_then(Value::as_u64).unwrap_or(TYPE_LOGIN);

    // Keep other clients' fields; rewrite ours.
    let mut out_fields: Vec<Value> = Vec::new();
    if let Some(c) = existing {
        let decrypted = fields(c, &key)?;
        let raw = c.get("fields").and_then(Value::as_array).cloned().unwrap_or_default();
        for ((name, _), f) in decrypted.iter().zip(raw) {
            if !name.starts_with(PREFIX) {
                out_fields.push(f);
            }
        }
    }
    let mut add = |name: &str, value: &str, ty: u64| {
        out_fields.push(
            json!({ "type": ty, "name": key.encrypt_str(name), "value": key.encrypt_str(value), "linkedId": null }),
        );
    };
    add(F_ID, &item.id, FIELD_TEXT);
    for (k, v) in &item.attributes {
        add(&format!("{F_ATTR}{k}"), v, FIELD_TEXT);
    }
    if item.content_type != "text/plain" {
        add(F_CONTENT_TYPE, &item.content_type, FIELD_TEXT);
    }
    if !item.acl.is_empty() {
        add(F_ACL, &item.acl.join("\n"), FIELD_HIDDEN);
    }
    add(F_CREATED, &item.created.to_string(), FIELD_TEXT);

    let (text, base64) = match std::str::from_utf8(&item.secret) {
        Ok(s) => (Zeroizing::new(s.to_owned()), false),
        Err(_) => (Zeroizing::new(B64.encode(&item.secret)), true),
    };
    if base64 {
        add(F_ENCODING, "base64", FIELD_TEXT);
    }
    let enc_secret = if text.is_empty() { None } else { Some(key.encrypt_str(&text)) };
    let len = enc_secret.as_ref().map_or(0, String::len);
    let in_notes = ty == TYPE_SECURE_NOTE || len > MAX_PASSWORD_ENC;
    if len > MAX_NOTES_ENC {
        return Err(MapError::TooLarge);
    }
    if in_notes && ty == TYPE_LOGIN {
        add(F_LOCATION, "notes", FIELD_TEXT);
    }

    let previous = existing.and_then(|c| c.pointer("/login/password")).and_then(Value::as_str).map(str::to_owned);
    if ty == TYPE_LOGIN {
        let mut login = existing.and_then(|c| c.get("login")).and_then(Value::as_object).cloned().unwrap_or_default();
        login.insert(
            "password".into(),
            if in_notes { Value::Null } else { enc_secret.clone().map_or(Value::Null, Value::String) },
        );
        login.entry("username").or_insert(Value::Null);
        login.entry("uris").or_insert(Value::Null);
        login.entry("totp").or_insert(Value::Null);
        body.insert("login".into(), Value::Object(login));
        if in_notes {
            body.insert("notes".into(), enc_secret.clone().map_or(Value::Null, Value::String));
        }
        // Keep the replaced password in the history, newest first, at most 5.
        let mut history =
            existing.and_then(|c| c.get("passwordHistory")).and_then(Value::as_array).cloned().unwrap_or_default();
        if let Some(prev) = previous.filter(|p| Some(p) != enc_secret.as_ref() && !in_notes) {
            history.insert(0, json!({ "password": prev, "lastUsedDate": format_date(crate::model::now()) }));
            history.truncate(5);
        }
        body.insert("passwordHistory".into(), Value::Array(history));
    } else {
        body.insert("notes".into(), enc_secret.map_or(Value::Null, Value::String));
        body.entry("secureNote").or_insert(json!({ "type": 0 }));
        body.entry("passwordHistory").or_insert(Value::Null);
    }

    body.insert("type".into(), json!(ty));
    body.insert("folderId".into(), json!(folder_id));
    body.insert("organizationId".into(), Value::Null);
    body.insert("name".into(), json!(key.encrypt_str(&item.label)));
    body.insert("fields".into(), Value::Array(out_fields));
    body.entry("favorite").or_insert(json!(false));
    body.entry("reprompt").or_insert(json!(0));
    body.entry("key").or_insert(Value::Null);
    body.entry("notes").or_insert(Value::Null);
    if let Some(rev) = existing.and_then(|c| c.get("revisionDate")) {
        body.insert("lastKnownRevisionDate".into(), rev.clone());
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bw::scan::{Keys, Scan, scan};
    use crate::model::Attributes;

    /// Reads an encoded item back the way the backend does.
    fn read_back(cipher: &Value, key: &SymmetricKey) -> ItemData {
        let keys = Keys { user: key.clone(), mark: key.derive("value-mark") };
        match scan(cipher, &keys) {
            Scan::Marked(m) => m.item,
            other => panic!("expected a marked item, got {other:?}"),
        }
    }

    fn own_attributes(item: &ItemData) -> Attributes {
        item.attributes.iter().filter(|(k, _)| !k.starts_with(PREFIX)).map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    fn item(secret: &[u8]) -> ItemData {
        let mut attributes = Attributes::new();
        attributes.insert("service".into(), "github".into());
        attributes.insert("user".into(), "me".into());
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

    fn as_server(mut body: Map<String, Value>, id: &str) -> Value {
        body.remove("lastKnownRevisionDate");
        body.insert("id".into(), json!(id));
        body.insert("revisionDate".into(), json!("2026-10-23T00:00:00Z"));
        Value::Object(body)
    }

    #[test]
    fn round_trips_text_secrets() {
        let key = SymmetricKey::generate();
        let it = item(b"ghp_123");
        let cipher = as_server(encode(&it, None, &key, "f").unwrap(), "cid");
        let back = read_back(&cipher, &key);
        assert_eq!(&*back.secret, b"ghp_123");
        assert_eq!(back.id, "abc123");
        assert_eq!(own_attributes(&back), it.attributes);
        assert_eq!(back.acl, it.acl);
        assert_eq!(back.created, it.created);
        assert_eq!(back.label, "GitHub token");
    }

    #[test]
    fn binary_secrets_are_base64_in_the_password() {
        let key = SymmetricKey::generate();
        let secret = [0, 159, 146, 150, 255];
        let body = encode(&item(&secret), None, &key, "f").unwrap();
        let stored = key.decrypt_str(body["login"]["password"].as_str().unwrap()).unwrap();
        assert_eq!(B64.decode(stored.as_bytes()).unwrap(), secret);
    }

    #[test]
    fn edit_preserves_foreign_fields_uris_and_history() {
        let key = SymmetricKey::generate();
        let mut cipher = as_server(encode(&item(b"old"), None, &key, "f").unwrap(), "cid");
        cipher["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "type": 0, "name": key.encrypt_str("mine"), "value": key.encrypt_str("keep") }));
        cipher["login"]["uris"] = json!([{ "uri": key.encrypt_str("https://github.com"), "match": null }]);
        cipher["sshKey"] = json!({ "privateKey": "2.unknown" });
        let mut edited = item(b"new");
        edited.attributes.remove("user");
        let body = encode(&edited, Some(&cipher), &key, "f").unwrap();
        assert_eq!(body["lastKnownRevisionDate"], json!("2026-10-23T00:00:00Z"));
        assert!(!body.contains_key("id"));
        assert_eq!(body["sshKey"], json!({ "privateKey": "2.unknown" }));
        assert_eq!(body["login"]["uris"], cipher["login"]["uris"]);
        assert_eq!(body["passwordHistory"][0]["password"], cipher["login"]["password"]);
        let back = read_back(&as_server(body, "cid"), &key);
        assert_eq!(&*back.secret, b"new");
        assert!(!back.attributes.contains_key("user"));
        let names: Vec<_> = fields(&as_server(encode(&edited, Some(&cipher), &key, "f").unwrap(), "cid"), &key)
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(names.contains(&"mine".to_owned()));
    }

    #[test]
    fn large_secrets_go_to_notes_and_huge_ones_are_refused() {
        let key = SymmetricKey::generate();
        let big = vec![b'x'; 5_000];
        let cipher = as_server(encode(&item(&big), None, &key, "f").unwrap(), "cid");
        assert!(cipher["login"]["password"].is_null());
        assert_eq!(read_back(&cipher, &key).secret.to_vec(), big);
        assert!(matches!(encode(&item(&vec![b'x'; 20_000]), None, &key, "f"), Err(MapError::TooLarge)));
    }

    #[test]
    fn per_item_keys() {
        let user = SymmetricKey::generate();
        let item_key = SymmetricKey::generate();
        let cipher = json!({
            "id": "x", "type": 1, "key": user.encrypt(&item_key.to_bytes()), "name": item_key.encrypt_str("L"),
            "login": { "password": item_key.encrypt_str("s") }, "revisionDate": ""
        });
        let body = encode(&item(b"t"), Some(&cipher), &user, "f").unwrap();
        assert_eq!(body["key"], cipher["key"]);
        assert_eq!(&*read_back(&as_server(body, "x"), &user).secret, b"t");
    }
}
