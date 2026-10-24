//! Marker scan: find the items that carry `bwss:id` and read them.
//!
//! The scan decrypts the item key and the custom-field **names** first. Only
//! an item with a non-blank marker is read any further; everything else
//! (name, notes, login, other field values) stays ciphertext.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use super::crypto::{CryptoError, SymmetricKey, value_mark};
use super::fields::{
    A_ID, A_NAME, A_URI, A_USERNAME, Encoding, F_ACL, F_ATTR, F_COLLECTION, F_CONTENT_TYPE, F_CREATED, F_ENCODING,
    F_ID, F_LABEL, F_LOCATION, F_PASSWORD, Location, field_names, field_value, first_index,
};
use super::items::{item_key, parse_date};
use crate::model::{Attributes, ItemData, LOGIN_COLLECTION, SESSION_COLLECTION};

const TYPE_LOGIN: u64 = 1;
const TYPE_SECURE_NOTE: u64 = 2;

/// Where a marked item's secret was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueSource {
    /// The `bwss:password` field.
    Field,
    /// The notes, because of `bwss:location=notes`.
    BwssNotes,
    /// A secure note's own text.
    NoteBody,
    /// A login's password.
    LoginPassword,
}

#[derive(Debug, Clone)]
pub struct MarkedItem {
    pub cipher_id: String,
    pub revision_date: String,
    /// `creationDate`, for duplicate resolution; `None` when the cipher has none.
    pub creation_date: Option<u64>,
    pub organization: bool,
    pub source: ValueSource,
    /// Mark of the stored text at `source`: decrypted, before any base64
    /// decoding, so a client re-encrypting the same value keeps the mark.
    pub mark: [u8; 32],
    /// `id` is the trimmed `bwss:id`, raw.
    pub item: ItemData,
}

#[derive(Debug)]
pub enum Scan {
    /// No marker (or a blank one), or in the trash.
    Unmarked,
    Marked(Box<MarkedItem>),
    /// Cannot be read; the reason carries no secret.
    Uninspectable(String),
    /// Readable but not supported; the reason carries no secret.
    Skipped(String),
}

pub struct Keys {
    pub user: SymmetricKey,
    pub mark: SymmetricKey,
}

/// Collection id from a `bwss:collection` value: trimmed and lowercased;
/// empty, `default` and `session` (memory only) all mean `login`.
pub fn normalize_collection(raw: &str) -> String {
    let id = raw.trim().to_lowercase();
    if id.is_empty() || id == "default" || id == SESSION_COLLECTION { LOGIN_COLLECTION.to_owned() } else { id }
}

fn str_at<'a>(cipher: &'a Value, pointer: &str) -> Option<&'a str> {
    cipher.pointer(pointer).and_then(Value::as_str)
}

fn dec_opt(raw: Option<&str>, key: &SymmetricKey) -> Result<Zeroizing<String>, CryptoError> {
    match raw {
        Some(s) if !s.is_empty() => key.decrypt_str(s),
        _ => Ok(Zeroizing::new(String::new())),
    }
}

/// Stored (still encrypted) value of the field at `index`; `""` for null.
fn stored_value(cipher: &Value, index: usize) -> &str {
    cipher.pointer(&format!("/fields/{index}/value")).and_then(Value::as_str).unwrap_or_default()
}

pub fn scan(cipher: &Value, keys: &Keys) -> Scan {
    let cipher_id = cipher.get("id").and_then(Value::as_str).unwrap_or_default();
    if cipher.get("deletedDate").is_some_and(|d| !d.is_null()) {
        return Scan::Unmarked;
    }
    if cipher.get("organizationId").is_some_and(|o| !o.is_null()) {
        return Scan::Uninspectable(format!("{cipher_id}: organization items are not read"));
    }
    let Ok(key) = item_key(cipher, &keys.user) else {
        return Scan::Uninspectable(format!("{cipher_id}: item key cannot be unwrapped"));
    };
    let Ok(names) = field_names(cipher, &key) else {
        return Scan::Uninspectable(format!("{cipher_id}: field names cannot be decrypted"));
    };
    let Some(id_index) = first_index(&names, F_ID) else {
        return Scan::Unmarked;
    };
    let Ok(id) = field_value(cipher, id_index, &key) else {
        return Scan::Uninspectable(format!("{cipher_id}: marker cannot be decrypted"));
    };
    let id = id.trim().to_owned();
    if id.is_empty() {
        return Scan::Unmarked;
    }
    match read_marked(cipher, cipher_id, &key, keys, &names, id) {
        Ok(r) => r,
        Err(_) => Scan::Uninspectable(format!("{cipher_id}: a value cannot be decrypted")),
    }
}

fn read_marked(
    cipher: &Value,
    cipher_id: &str,
    key: &SymmetricKey,
    keys: &Keys,
    names: &[Option<String>],
    id: String,
) -> Result<Scan, CryptoError> {
    let ty = cipher.get("type").and_then(Value::as_u64).unwrap_or(0);
    if ty != TYPE_LOGIN && ty != TYPE_SECURE_NOTE {
        return Ok(Scan::Skipped(format!("{cipher_id}: item type {ty} is not supported")));
    }
    let field = |name: &str| -> Result<Option<Zeroizing<String>>, CryptoError> {
        first_index(names, name).map(|i| field_value(cipher, i, key)).transpose()
    };

    let location = field(F_LOCATION)?;
    // Only the value `notes` is a mark; an empty or blank one counts as
    // absent (spec §5, §6.4, ADR 0010).
    let in_notes = match Location::classify(location.as_deref().map(String::as_str)) {
        Location::Absent => false,
        Location::Notes => true,
        Location::Unknown => return Ok(Scan::Skipped(format!("{cipher_id}: unknown {F_LOCATION}"))),
    };
    let encoding = field(F_ENCODING)?;
    let base64 = match Encoding::classify(encoding.as_deref().map(String::as_str)) {
        Encoding::Absent => false,
        Encoding::Base64 => true,
        Encoding::Unknown => return Ok(Scan::Skipped(format!("{cipher_id}: unknown {F_ENCODING}"))),
    };

    // The value source: the first present one.
    let password_index = first_index(names, F_PASSWORD);
    let (source, stored) = if let Some(i) = password_index {
        (ValueSource::Field, stored_value(cipher, i))
    } else if in_notes || ty == TYPE_SECURE_NOTE {
        let source = if in_notes { ValueSource::BwssNotes } else { ValueSource::NoteBody };
        (source, str_at(cipher, "/notes").unwrap_or_default())
    } else {
        (ValueSource::LoginPassword, str_at(cipher, "/login/password").unwrap_or_default())
    };
    // Never decrypt (or decode) a value the user owns when base64 is asked of it.
    if base64 && matches!(source, ValueSource::LoginPassword | ValueSource::NoteBody) {
        return Ok(Scan::Skipped(format!("{cipher_id}: {F_ENCODING}=base64 on a value bwss does not own")));
    }
    let text = match password_index {
        Some(i) => field_value(cipher, i, key)?,
        None => dec_opt(Some(stored), key)?,
    };
    let secret = if base64 {
        match B64.decode(text.as_bytes()) {
            Ok(b) => Zeroizing::new(b),
            Err(_) => return Ok(Scan::Skipped(format!("{cipher_id}: value is not valid base64"))),
        }
    } else {
        Zeroizing::new(text.as_bytes().to_vec())
    };
    // Over the decrypted text, never the ciphertext: official clients
    // re-encrypt every value with a fresh IV on any save.
    let mark = value_mark(&keys.mark, &id, &text);

    // Derived attributes and the item name.
    let name = dec_opt(str_at(cipher, "/name"), key)?;
    let username = dec_opt(str_at(cipher, "/login/username"), key)?;
    let uri = dec_opt(str_at(cipher, "/login/uris/0/uri"), key)?;

    let mut attributes = Attributes::new();
    for (i, n) in names.iter().enumerate() {
        let Some(attr) = n.as_deref().and_then(|n| n.strip_prefix(F_ATTR)) else { continue };
        if attr.is_empty() || [A_ID, A_NAME, A_USERNAME, A_URI].contains(&attr) || attributes.contains_key(attr) {
            continue;
        }
        attributes.insert(attr.to_owned(), field_value(cipher, i, key)?.to_string());
    }
    attributes.insert(A_ID.to_owned(), id.clone());
    for (k, v) in [(A_NAME, &name), (A_USERNAME, &username), (A_URI, &uri)] {
        if !v.is_empty() {
            attributes.insert(k.to_owned(), v.to_string());
        }
    }

    let label = field(F_LABEL)?.filter(|l| !l.is_empty()).map_or_else(|| name.to_string(), |l| l.to_string());
    let collection = match field(F_COLLECTION)? {
        None => LOGIN_COLLECTION.to_owned(),
        Some(c) => {
            if c.trim().eq_ignore_ascii_case(SESSION_COLLECTION) {
                tracing::warn!("{cipher_id}: {F_COLLECTION}=session is memory only; the item stays in login");
            }
            normalize_collection(&c)
        }
    };
    let content_type =
        field(F_CONTENT_TYPE)?.filter(|c| !c.is_empty()).map_or_else(|| "text/plain".to_owned(), |c| c.to_string());
    let revision_date = cipher.get("revisionDate").and_then(Value::as_str).unwrap_or_default().to_owned();
    let modified = parse_date(&revision_date);
    let creation_date = cipher.get("creationDate").and_then(Value::as_str).map(parse_date).filter(|&d| d != 0);
    let created = field(F_CREATED)?.and_then(|s| s.trim().parse().ok()).or(creation_date).unwrap_or(0);
    let acl = field(F_ACL)?
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).map(str::to_owned).collect())
        .unwrap_or_default();

    Ok(Scan::Marked(Box::new(MarkedItem {
        cipher_id: cipher_id.to_owned(),
        revision_date,
        creation_date,
        organization: false,
        source,
        mark,
        item: ItemData { id, collection, label, attributes, secret, content_type, created, modified, acl },
    })))
}

/// Picks one item per `bwss:id`. The winner is a personal item over an
/// organization one, then a dated one over an undated one, then the oldest,
/// then the lowest cipher id, so every device chooses alike. Returns the
/// winners and `(id, losing cipher ids)` sorted by id.
pub fn resolve_duplicates(items: Vec<MarkedItem>) -> (Vec<MarkedItem>, Vec<(String, Vec<String>)>) {
    let mut groups: std::collections::BTreeMap<String, Vec<MarkedItem>> = std::collections::BTreeMap::new();
    for item in items {
        groups.entry(item.item.id.clone()).or_default().push(item);
    }
    let mut winners = Vec::new();
    let mut losers = Vec::new();
    for (id, mut group) in groups {
        group.sort_by(|a, b| {
            (a.organization, a.creation_date.is_none(), a.creation_date, &a.cipher_id).cmp(&(
                b.organization,
                b.creation_date.is_none(),
                b.creation_date,
                &b.cipher_id,
            ))
        });
        let mut rest = group.into_iter();
        winners.extend(rest.next());
        let mut lost: Vec<String> = rest.map(|m| m.cipher_id).collect();
        if !lost.is_empty() {
            lost.sort();
            losers.push((id, lost));
        }
    }
    (winners, losers)
}

#[cfg(test)]
#[expect(clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use serde_json::json;

    fn keys() -> Keys {
        Keys { user: SymmetricKey::generate(), mark: SymmetricKey::generate() }
    }

    fn f(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    fn enc_fields(k: &Keys, fields: &[(String, String)]) -> Value {
        Value::Array(
            fields
                .iter()
                .map(|(n, v)| json!({ "type": 0, "name": k.user.encrypt_str(n), "value": k.user.encrypt_str(v) }))
                .collect(),
        )
    }

    fn login(k: &Keys, fields: &[(String, String)], password: Option<&str>, notes: Option<&str>) -> Value {
        json!({
            "id": "c1", "type": 1, "revisionDate": "2026-01-02T03:04:05Z", "creationDate": "2025-01-02T03:04:05Z",
            "name": k.user.encrypt_str("GitHub"),
            "notes": notes.map(|n| k.user.encrypt_str(n)),
            "login": {
                "username": k.user.encrypt_str("me"),
                "password": password.map(|p| k.user.encrypt_str(p)),
                "uris": [{ "uri": k.user.encrypt_str("https://github.com"), "match": null }],
            },
            "fields": enc_fields(k, fields),
        })
    }

    fn note(k: &Keys, fields: &[(String, String)], notes: Option<&str>) -> Value {
        json!({
            "id": "n1", "type": 2, "revisionDate": "2026-01-02T03:04:05Z", "creationDate": "2025-01-02T03:04:05Z",
            "name": k.user.encrypt_str("Note"),
            "notes": notes.map(|n| k.user.encrypt_str(n)),
            "secureNote": { "type": 0 },
            "fields": enc_fields(k, fields),
        })
    }

    fn marked(s: Scan) -> Box<MarkedItem> {
        let Scan::Marked(m) = s else { panic!() };
        m
    }

    #[test]
    fn unmarked_items_stay_encrypted() {
        // name, notes, login and other field values are invalid ciphertext:
        // touching any of them would make the scan fail.
        let k = keys();
        let c = json!({ "id": "c1", "type": 1, "name": "2.bad|bad|bad", "notes": "2.bad|bad|bad",
            "login": { "password": "2.bad|bad|bad", "username": "2.bad|bad|bad" },
            "fields": [{ "type": 0, "name": k.user.encrypt_str("other"), "value": "2.bad|bad|bad" }] });
        assert!(matches!(scan(&c, &k), Scan::Unmarked));
    }

    #[test]
    fn secret_comes_from_the_first_present_source() {
        let k = keys();
        // empty bwss:password still wins over the login password
        let s = marked(scan(&login(&k, &[f("bwss:id", "x"), f("bwss:password", "")], Some("pw"), None), &k));
        assert_eq!((s.item.secret.as_slice(), s.source), (&b""[..], ValueSource::Field));
        let s = marked(scan(&login(&k, &[f("bwss:id", "x")], Some("pw"), Some("n")), &k));
        assert_eq!((s.item.secret.as_slice(), s.source), (&b"pw"[..], ValueSource::LoginPassword));
        let s = marked(scan(&note(&k, &[f("bwss:id", "x")], Some("body")), &k));
        assert_eq!((s.item.secret.as_slice(), s.source), (&b"body"[..], ValueSource::NoteBody));
        let s =
            marked(scan(&login(&k, &[f("bwss:id", "x"), f("bwss:location", "notes")], Some("pw"), Some("big")), &k));
        assert_eq!((s.item.secret.as_slice(), s.source), (&b"big"[..], ValueSource::BwssNotes));
        let c = note(&k, &[f("bwss:id", "x"), f("bwss:encoding", "base64"), f("bwss:password", "AAE=")], None);
        let s = marked(scan(&c, &k));
        assert_eq!(s.item.secret.as_slice(), &[0u8, 1][..]);
        // the mark follows the stored text, decrypted but not decoded
        assert_eq!(s.mark, value_mark(&k.mark, "x", "AAE="));
    }

    #[test]
    fn label_attributes_and_defaults() {
        let k = keys();
        let c = login(
            &k,
            &[f("bwss:id", " gh "), f("bwss:attr:service", "git"), f("bwss:attr:bwss:name", "spoof")],
            Some("pw"),
            None,
        );
        let s = marked(scan(&c, &k));
        assert_eq!(s.item.id, "gh");
        assert_eq!(s.item.label, "GitHub");
        assert_eq!(s.item.collection, "login");
        assert_eq!(s.item.content_type, "text/plain");
        assert_eq!(s.item.attributes.get("service").map(String::as_str), Some("git"));
        assert_eq!(s.item.attributes.get("bwss:name").map(String::as_str), Some("GitHub"));
        assert_eq!(s.item.attributes.get("bwss:id").map(String::as_str), Some("gh"));
        assert_eq!(s.item.attributes.get("bwss:username").map(String::as_str), Some("me"));
        assert_eq!(s.item.attributes.get("bwss:uri").map(String::as_str), Some("https://github.com"));
        assert_eq!(s.item.created, 1_735_787_045); // creationDate
        assert_eq!(s.item.modified, 1_767_323_045);
        assert_eq!(s.creation_date, Some(1_735_787_045));
        assert_eq!(s.cipher_id, "c1");
        // bwss:label wins over the name; bwss:created wins over creationDate
        let c = login(
            &k,
            &[
                f("bwss:id", "gh"),
                f("bwss:label", "Mine"),
                f("bwss:created", "42"),
                f("bwss:acl", "/a\n\n/b\n"),
                f("bwss:collection", "Work/Keys"),
                f("bwss:content-type", "text/x"),
            ],
            Some("pw"),
            None,
        );
        let s = marked(scan(&c, &k));
        assert_eq!((s.item.label.as_str(), s.item.created), ("Mine", 42));
        assert_eq!(s.item.acl, vec!["/a".to_owned(), "/b".to_owned()]);
        assert_eq!((s.item.collection.as_str(), s.item.content_type.as_str()), ("work/keys", "text/x"));
    }

    #[test]
    fn duplicate_fields_first_wins() {
        let k = keys();
        let c = login(
            &k,
            &[f("bwss:id", "a"), f("bwss:id", "b"), f("bwss:password", "1"), f("bwss:password", "2")],
            None,
            None,
        );
        let s = marked(scan(&c, &k));
        assert_eq!((s.item.id.as_str(), s.item.secret.as_slice()), ("a", &b"1"[..]));
    }

    #[test]
    fn blank_marker_reads_nothing_else() {
        let k = keys();
        let mut c = login(&k, &[f("bwss:id", "  ")], Some("pw"), None);
        c["name"] = json!("2.bad|bad|bad");
        c["notes"] = json!("2.bad|bad|bad");
        c["login"]["password"] = json!("2.bad|bad|bad");
        assert!(matches!(scan(&c, &k), Scan::Unmarked));
    }

    #[test]
    fn collection_values_normalize() {
        assert_eq!(normalize_collection(" Default "), "login");
        assert_eq!(normalize_collection("Session"), "login");
        assert_eq!(normalize_collection("Work/Keys"), "work/keys");
        assert_eq!(normalize_collection(""), "login");
    }

    #[test]
    fn what_is_skipped_or_uninspectable() {
        let k = keys();
        let id = f("bwss:id", "x");
        // card (type 3) with a marker -> Skipped
        let mut card = login(&k, std::slice::from_ref(&id), None, None);
        card["type"] = json!(3);
        assert!(matches!(scan(&card, &k), Scan::Skipped(_)));
        // bwss:location = "attachment" -> Skipped
        let c = login(&k, &[id.clone(), f("bwss:location", "attachment")], Some("pw"), None);
        assert!(matches!(scan(&c, &k), Scan::Skipped(_)));
        // bwss:encoding = "hex" -> Skipped
        let c = login(&k, &[id.clone(), f("bwss:encoding", "hex")], Some("pw"), None);
        assert!(matches!(scan(&c, &k), Scan::Skipped(_)));
        // bwss:encoding = "base64" with source LoginPassword -> Skipped (ADR 0005)
        let mut c = login(&k, &[id.clone(), f("bwss:encoding", "base64")], Some("AAE="), None);
        c["login"]["password"] = json!("2.bad|bad|bad"); // proves the value is not decrypted
        assert!(matches!(scan(&c, &k), Scan::Skipped(_)));
        // bwss:encoding = "base64" with source NoteBody -> Skipped (ADR 0005)
        let mut c = note(&k, &[id.clone(), f("bwss:encoding", "base64")], Some("AAE="));
        c["notes"] = json!("2.bad|bad|bad"); // proves the value is not decrypted
        assert!(matches!(scan(&c, &k), Scan::Skipped(_)));
        // organizationId set -> Uninspectable (organizations are not read in v1)
        let mut c = login(&k, std::slice::from_ref(&id), Some("pw"), None);
        c["organizationId"] = json!("org1");
        assert!(matches!(scan(&c, &k), Scan::Uninspectable(_)));
        // cipher.key that does not unwrap -> Uninspectable
        let mut c = login(&k, std::slice::from_ref(&id), Some("pw"), None);
        c["key"] = json!("2.bad|bad|bad");
        assert!(matches!(scan(&c, &k), Scan::Uninspectable(_)));
        // deletedDate set -> Unmarked (the trash is not scanned)
        let mut c = login(&k, std::slice::from_ref(&id), Some("pw"), None);
        c["deletedDate"] = json!("2026-01-01T00:00:00Z");
        assert!(matches!(scan(&c, &k), Scan::Unmarked));
        // "bwss:id" present but blank after trim -> Unmarked
        let c = login(&k, &[f("bwss:id", "  ")], Some("pw"), None);
        assert!(matches!(scan(&c, &k), Scan::Unmarked));
        // empty or blank bwss:location counts as absent (ADR 0010)
        for blank in ["", "  ", "\t\n"] {
            let c = login(&k, &[id.clone(), f("bwss:location", blank)], Some("pw"), Some("mine"));
            let m = marked(scan(&c, &k));
            assert_eq!((m.source, m.item.secret.as_slice()), (ValueSource::LoginPassword, b"pw".as_slice()));
        }
        // only "notes" (after trimming) is the mark: anything else is unknown
        for odd in ["Notes", "hex"] {
            let c = login(&k, &[id.clone(), f("bwss:location", odd)], Some("pw"), Some("mine"));
            assert!(matches!(scan(&c, &k), Scan::Skipped(_)), "{odd:?}");
            let c = login(&k, &[id.clone(), f("bwss:encoding", odd)], Some("pw"), Some("mine"));
            assert!(matches!(scan(&c, &k), Scan::Skipped(_)), "{odd:?}");
        }
        // a padded mark is the mark (ADR 0014)
        let c = login(&k, &[id.clone(), f("bwss:location", " notes\n")], None, Some("big"));
        let m = marked(scan(&c, &k));
        assert_eq!((m.source, m.item.secret.as_slice()), (ValueSource::BwssNotes, b"big".as_slice()));
        let c = login(&k, &[id.clone(), f("bwss:encoding", " base64\n"), f("bwss:password", "AAE=")], None, None);
        let m = marked(scan(&c, &k));
        assert_eq!(m.item.secret.as_slice(), [0u8, 1].as_slice());
        // a blank encoding is absent: the value is read as text
        let c = login(&k, &[id.clone(), f("bwss:encoding", "  "), f("bwss:password", "AAE=")], None, None);
        assert_eq!(marked(scan(&c, &k)).item.secret.as_slice(), b"AAE=".as_slice());
        // undecryptable field names -> Uninspectable
        let mut c = login(&k, std::slice::from_ref(&id), Some("pw"), None);
        c["fields"][0]["name"] = json!("2.bad|bad|bad");
        assert!(matches!(scan(&c, &k), Scan::Uninspectable(_)));
        // a marker value that does not decrypt -> Uninspectable, named by cipher id
        let mut c = login(&k, std::slice::from_ref(&id), Some("pw"), None);
        c["fields"][0]["value"] = json!("2.bad|bad|bad");
        assert!(matches!(scan(&c, &k), Scan::Uninspectable(why) if why == "c1: marker cannot be decrypted"));
        // a later value that does not decrypt -> Uninspectable, never a partial item
        let mut c = login(&k, &[id.clone(), f("bwss:password", "pw")], None, None);
        c["fields"][1]["value"] = json!("2.bad|bad|bad");
        assert!(matches!(scan(&c, &k), Scan::Uninspectable(why) if why == "c1: a value cannot be decrypted"));
        // base64 that does not decode -> Skipped
        let c =
            login(&k, &[id.clone(), f("bwss:encoding", "base64"), f("bwss:password", "!!not base64!!")], None, None);
        assert!(matches!(scan(&c, &k), Scan::Skipped(why) if why == "c1: value is not valid base64"));
        // the memory-only session collection falls back to login
        let c = login(&k, &[id.clone(), f("bwss:collection", " Session ")], Some("pw"), None);
        assert_eq!(marked(scan(&c, &k)).item.collection, "login");
        // unparseable creationDate -> no date, so it sorts last
        let mut c = login(&k, std::slice::from_ref(&id), Some("pw"), None);
        c["creationDate"] = json!("not a date");
        assert_eq!(marked(scan(&c, &k)).creation_date, None);
        // reasons never carry item content
        let c = login(&k, &[id, f("bwss:location", "attachment")], Some("pw"), None);
        let Scan::Skipped(why) = scan(&c, &k) else { panic!() };
        assert!(!why.contains("pw") && !why.contains("GitHub"));
    }

    type Spec = (&'static str, &'static str, bool, Option<u64>);

    fn m((id, cipher_id, org, created): Spec) -> MarkedItem {
        MarkedItem {
            cipher_id: cipher_id.to_owned(),
            revision_date: String::new(),
            creation_date: created,
            organization: org,
            source: ValueSource::LoginPassword,
            mark: [0; 32],
            item: ItemData {
                id: id.to_owned(),
                collection: "default".to_owned(),
                label: String::new(),
                attributes: Attributes::default(),
                secret: Zeroizing::new(Vec::new()),
                content_type: "text/plain".to_owned(),
                created: 0,
                modified: 0,
                acl: Vec::new(),
            },
        }
    }

    fn permutations<T: Copy>(items: &[T]) -> Vec<Vec<T>> {
        if items.len() <= 1 {
            return vec![items.to_vec()];
        }
        let mut out = Vec::new();
        for i in 0..items.len() {
            let mut rest = items.to_vec();
            let head = rest.remove(i);
            for mut tail in permutations(&rest) {
                tail.insert(0, head);
                out.push(tail);
            }
        }
        out
    }

    #[test]
    fn duplicates_resolve_the_same_way_in_any_order() {
        // a: org, oldest; b: personal, created 200; c: personal, created 100; d: personal, no date
        let all = [
            ("x", "a", true, Some(50)),
            ("x", "b", false, Some(200)),
            ("x", "c", false, Some(100)),
            ("x", "d", false, None),
        ];
        for perm in permutations(&all) {
            let (win, lost) = resolve_duplicates(perm.into_iter().map(m).collect());
            assert_eq!(win.len(), 1);
            assert_eq!(win[0].cipher_id, "c");
            assert_eq!(lost, vec![("x".to_owned(), vec!["a".to_owned(), "b".to_owned(), "d".to_owned()])]);
        }
        // same date: lowest cipher id wins
        for perm in permutations(&[("x", "q", false, Some(7)), ("x", "p", false, Some(7))]) {
            let (win, lost) = resolve_duplicates(perm.into_iter().map(m).collect());
            assert_eq!(win[0].cipher_id, "p");
            assert_eq!(lost, vec![("x".to_owned(), vec!["q".to_owned()])]);
        }
    }

    #[test]
    fn distinct_ids_all_win_and_losers_are_sorted_by_id() {
        let (win, lost) = resolve_duplicates(vec![m(("a", "c1", false, None)), m(("b", "c2", true, Some(1)))]);
        assert_eq!(win.len(), 2);
        assert!(lost.is_empty());

        let all = [
            ("z", "z2", false, Some(2)),
            ("z", "z1", false, Some(1)),
            ("m", "m2", false, Some(2)),
            ("m", "m1", false, Some(1)),
            ("solo", "s", false, None),
            ("c", "c3", true, None),
            ("c", "c1", false, None),
        ];
        let expected = vec![
            ("c".to_owned(), vec!["c3".to_owned()]),
            ("m".to_owned(), vec!["m2".to_owned()]),
            ("z".to_owned(), vec!["z2".to_owned()]),
        ];
        for perm in permutations(&all) {
            let (win, lost) = resolve_duplicates(perm.into_iter().map(m).collect());
            let mut ids: Vec<_> = win.iter().map(|w| (w.item.id.as_str(), w.cipher_id.as_str())).collect();
            ids.sort();
            assert_eq!(ids, [("c", "c1"), ("m", "m1"), ("solo", "s"), ("z", "z1")]);
            assert_eq!(lost, expected);
        }
    }
}
