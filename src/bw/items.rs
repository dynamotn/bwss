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
use crate::model::{Attributes, ItemData, path_segment};

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
const MAX_PASSWORD_ENC: usize = 5_000;
const MAX_NOTES_ENC: usize = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum MapError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("secret is too large for a Bitwarden item")]
    TooLarge,
    #[error("item type {0} is not supported")]
    UnsupportedType(u64),
}

pub fn parse_date(s: &str) -> u64 {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|t| u64::try_from(t.unix_timestamp()).unwrap_or(0))
        .unwrap_or(0)
}

fn format_date(secs: u64) -> String {
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

/// Decodes a Bitwarden item into a Secret Service item of `collection`.
pub fn decode(cipher: &Value, user_key: &SymmetricKey, collection: &str) -> Result<ItemData, MapError> {
    let ty = cipher.get("type").and_then(Value::as_u64).unwrap_or(0);
    if ty != TYPE_LOGIN && ty != TYPE_SECURE_NOTE {
        return Err(MapError::UnsupportedType(ty));
    }
    let key = item_key(cipher, user_key)?;
    let fields = fields(cipher, &key)?;
    let get = |name: &str| fields.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str().to_owned());

    let mut attributes = Attributes::new();
    for (name, value) in &fields {
        if let Some(attr) = name.strip_prefix(F_ATTR) {
            attributes.insert(attr.to_owned(), value.to_string());
        }
    }
    let in_notes = get(F_LOCATION).as_deref() == Some("notes") || ty == TYPE_SECURE_NOTE;
    let raw = if in_notes { cipher.get("notes") } else { cipher.pointer("/login/password") };
    let text = dec(raw, &key)?.unwrap_or_default();
    let secret = if get(F_ENCODING).as_deref() == Some("base64") {
        Zeroizing::new(B64.decode(text.as_bytes()).map_err(|_| CryptoError::Decrypt)?)
    } else {
        Zeroizing::new(text.as_bytes().to_vec())
    };
    let cipher_id = cipher.get("id").and_then(Value::as_str).unwrap_or_default();
    let modified = parse_date(cipher.get("revisionDate").and_then(Value::as_str).unwrap_or_default());
    Ok(ItemData {
        id: get(F_ID)
            .filter(|s| !s.is_empty())
            .map(|s| path_segment(&s))
            .unwrap_or_else(|| format!("c{}", path_segment(cipher_id))),
        collection: collection.to_owned(),
        label: dec(cipher.get("name"), &key)?.map(|s| s.to_string()).unwrap_or_default(),
        attributes,
        secret,
        content_type: get(F_CONTENT_TYPE).unwrap_or_else(|| "text/plain".into()),
        created: get(F_CREATED).and_then(|s| s.parse().ok()).unwrap_or(modified),
        modified,
        acl: get(F_ACL).map(|s| s.lines().filter(|l| !l.is_empty()).map(str::to_owned).collect()).unwrap_or_default(),
    })
}

/// Response-only properties that must not be echoed back in a write.
const RESPONSE_ONLY: &[&str] = &[
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
    use crate::model::Attributes;

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
    fn round_trips_text_and_binary_secrets() {
        let key = SymmetricKey::generate();
        for secret in [b"ghp_123".to_vec(), vec![0, 159, 146, 150, 255]] {
            let it = item(&secret);
            let cipher = as_server(encode(&it, None, &key, "f").unwrap(), "cid");
            let back = decode(&cipher, &key, "login").unwrap();
            assert_eq!(back.secret.to_vec(), secret);
            assert_eq!(back.id, "abc123");
            assert_eq!(back.attributes, it.attributes);
            assert_eq!(back.acl, it.acl);
            assert_eq!(back.created, it.created);
            assert_eq!(back.label, "GitHub token");
        }
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
        let back = decode(&as_server(body, "cid"), &key, "login").unwrap();
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
        assert_eq!(decode(&cipher, &key, "login").unwrap().secret.to_vec(), big);
        assert!(matches!(encode(&item(&vec![b'x'; 20_000]), None, &key, "f"), Err(MapError::TooLarge)));
    }

    #[test]
    fn decodes_items_made_by_other_clients() {
        let key = SymmetricKey::generate();
        let login = json!({
            "id": "1234-abcd", "type": 1, "name": key.encrypt_str("Bank"), "revisionDate": "2026-01-02T03:04:05Z",
            "login": { "username": key.encrypt_str("me"), "password": key.encrypt_str("hunter2") }, "fields": null
        });
        let it = decode(&login, &key, "login").unwrap();
        assert_eq!(it.id, "c1234_abcd");
        assert_eq!(&*it.secret, b"hunter2");
        assert_eq!(it.modified, 1_767_323_045);
        let note = json!({ "id": "n", "type": 2, "name": key.encrypt_str("Note"), "notes": key.encrypt_str("text"), "revisionDate": "" });
        assert_eq!(&*decode(&note, &key, "login").unwrap().secret, b"text");
        assert!(matches!(decode(&json!({ "type": 3 }), &key, "login"), Err(MapError::UnsupportedType(3))));
    }

    #[test]
    fn per_item_keys() {
        let user = SymmetricKey::generate();
        let item_key = SymmetricKey::generate();
        let cipher = json!({
            "id": "x", "type": 1, "key": user.encrypt(&item_key.to_bytes()), "name": item_key.encrypt_str("L"),
            "login": { "password": item_key.encrypt_str("s") }, "revisionDate": ""
        });
        assert_eq!(&*decode(&cipher, &user, "login").unwrap().secret, b"s");
        let body = encode(&item(b"t"), Some(&cipher), &user, "f").unwrap();
        assert_eq!(body["key"], cipher["key"]);
        assert_eq!(&*decode(&as_server(body, "x"), &user, "login").unwrap().secret, b"t");
    }
}
