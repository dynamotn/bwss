//! The dybw conformance vectors (`dybw-core/vectors/generated/bwss/`), run
//! against bwss's real read and write code.
//!
//! Opt-in: `cargo test --features vectors vectors::`. The vectors are found
//! at `DYBW_VECTORS_DIR`, else at `../core/vectors` next to the crate (the
//! umbrella layout). The format and every comparison rule are in the
//! vectors' `README.md`.
//!
//! Rust's test harness cannot register one test per file, so each kind of
//! scenario is one test that runs every vector of that kind, prints each
//! result, and passes only when the vectors that fail are exactly the ones
//! listed in `tests/vectors-expected-failures.txt`: a listed vector that
//! passes fails the test, so the list stays honest.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::backend::bitwarden::build;
use crate::bw::api::normalize_keys;
use crate::bw::crypto::SymmetricKey;
use crate::bw::items::item_key;
use crate::bw::scan::{Keys, Scan, ValueSource, scan};
use crate::bw::write::{Patch, ValueChange, WriteError, apply, has_foreign_content, new_note, strip};
use crate::model::{Attributes, ItemData, LOGIN_COLLECTION, now};

const NAMESPACE: &str = "bwss";
const NOT_FOUND: &str = "conformance vectors not found: set DYBW_VECTORS_DIR";
const EXPECTED_FAILURES: &str = "tests/vectors-expected-failures.txt";
/// Derived attributes (`fields::DERIVED`): compared only when a vector lists them.
const DERIVED: [&str; 4] = ["bwss:id", "bwss:name", "bwss:username", "bwss:uri"];

/// bwss's skip reasons (`Scan::Skipped` and the registry check in `build`)
/// mapped to the shared reason codes. A reason with no code is reported as
/// is, so it can never match an expectation.
const REASONS: &[(&str, &str)] = &[
    ("is not supported", "wrong-type"),
    ("unknown bwss:location", "unknown-location"),
    ("unknown bwss:encoding", "unknown-encoding"),
    ("bwss:encoding=base64 on a value bwss does not own", "encoding-on-user-source"),
    ("is reserved", "reserved-id"),
];

fn reason_code(why: &str) -> String {
    REASONS.iter().find(|(text, _)| why.contains(text)).map_or_else(|| why.to_owned(), |(_, code)| (*code).to_owned())
}

fn source_name(source: ValueSource) -> &'static str {
    match source {
        ValueSource::Field => "field",
        ValueSource::BwssNotes => "notes",
        ValueSource::NoteBody => "note-body",
        ValueSource::LoginPassword => "login-password",
    }
}

fn vectors_dir() -> PathBuf {
    let dir = std::env::var_os("DYBW_VECTORS_DIR")
        .map_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/vectors"), PathBuf::from);
    if !dir.join("generated").is_dir() {
        panic!("{NOT_FOUND}");
    }
    dir
}

fn read_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn json_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            json_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

/// `(vector id, vector)` for every generated bwss scenario, sorted by id.
fn scenarios(dir: &Path) -> Vec<(String, Value)> {
    let mut files = Vec::new();
    json_files(&dir.join("generated").join(NAMESPACE), &mut files);
    let mut out: Vec<(String, Value)> = files
        .iter()
        .map(|path| {
            let v = read_json(path);
            let id = v.get("id").and_then(Value::as_str).unwrap_or_else(|| panic!("{}: no id", path.display()));
            (id.to_owned(), v)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// `vector id -> reason` from the expected-failures file: one
/// `<vector id> <reason>` per line; blank lines and `#` comments are ignored.
fn expected_failures() -> BTreeMap<String, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(EXPECTED_FAILURES);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (id, reason) = line.split_once(' ').unwrap_or((line, ""));
        assert!(!reason.trim().is_empty(), "{EXPECTED_FAILURES}: {id} has no reason");
        assert!(out.insert(id.to_owned(), reason.trim().to_owned()).is_none(), "{EXPECTED_FAILURES}: {id} twice");
    }
    out
}

/// The keys bwss holds once unlocked: the account's user key, and the mark
/// key derived from it as `BitwardenBackend::unlock` does.
fn account_keys(dir: &Path, name: &str) -> Keys {
    let account = read_json(&dir.join("accounts").join(format!("{name}.json")));
    let raw = account.get("userKey").and_then(Value::as_str).unwrap_or_else(|| panic!("{name}: no userKey"));
    let bytes = Zeroizing::new(B64.decode(raw).unwrap_or_else(|e| panic!("{name}: userKey: {e}")));
    let user = SymmetricKey::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: userKey: {e}"));
    Keys { mark: user.derive("value-mark"), user }
}

/// The ciphers as bwss's API layer hands them on (`api::parse_body`).
fn server_ciphers(v: &Value) -> Vec<Value> {
    v.get("ciphers").and_then(Value::as_array).into_iter().flatten().cloned().map(normalize_keys).collect()
}

fn value_text(secret: &[u8]) -> String {
    match std::str::from_utf8(secret) {
        Ok(text) => text.to_owned(),
        Err(_) => format!("base64:{}", B64.encode(secret)),
    }
}

fn operation_secret(value: &str) -> Result<Vec<u8>, String> {
    match value.strip_prefix("base64:") {
        Some(b64) => B64.decode(b64).map_err(|e| format!("operation value: {e}")),
        None => Ok(value.as_bytes().to_vec()),
    }
}

// --- reads -------------------------------------------------------------------

fn by_key(list: &mut [Value], key: &str) {
    list.sort_by(|a, b| a.get(key).map(Value::to_string).cmp(&b.get(key).map(Value::to_string)));
}

/// What bwss reads from the vector's ciphers, in the shape of `expect.read`.
/// `expected` says which items list attributes.
fn actual_read(ciphers: &[Value], keys: &Keys, expected: &Value) -> Value {
    let built = build(&json!({ "ciphers": ciphers }), keys, None);
    let listed_attributes: HashMap<&str, &Map<String, Value>> = expected
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|i| Some((i.get("cipher")?.as_str()?, i.get("attributes")?.as_object()?)))
        .collect();
    let mut items: Vec<Value> = built
        .marked
        .values()
        .map(|m| {
            let mut item = json!({
                "cipher": m.cipher_id,
                "id": m.item.id,
                "value": value_text(&m.item.secret),
                "source": source_name(m.source),
            });
            if let (Some(listed), Some(o)) = (listed_attributes.get(m.cipher_id.as_str()), item.as_object_mut()) {
                let attributes: Map<String, Value> = m
                    .item
                    .attributes
                    .iter()
                    .filter(|(k, _)| !DERIVED.contains(&k.as_str()) || listed.contains_key(k.as_str()))
                    .map(|(k, v)| (k.clone(), json!(v)))
                    .collect();
                o.insert("attributes".into(), Value::Object(attributes));
            }
            item
        })
        .collect();
    items.sort_by(|a, b| {
        (a.get("id").map(Value::to_string), a.get("cipher").map(Value::to_string))
            .cmp(&(b.get("id").map(Value::to_string), b.get("cipher").map(Value::to_string)))
    });
    let mut skipped: Vec<Value> =
        built.skipped.iter().map(|(cid, why)| json!({ "cipher": cid, "reason": reason_code(why) })).collect();
    by_key(&mut skipped, "cipher");
    let mut uninspectable: Vec<String> = ciphers
        .iter()
        .filter(|c| matches!(scan(c, keys), Scan::Uninspectable(_)))
        .filter_map(|c| c.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    uninspectable.sort();
    let duplicates: Vec<Value> = built
        .duplicates
        .iter()
        .map(|(id, left)| json!({ "id": id, "kept": built.marked.get(id).map(|m| m.cipher_id.clone()), "left": left }))
        .collect();
    json!({ "items": items, "skipped": skipped, "uninspectable": uninspectable, "duplicates": duplicates })
}

/// `expect.read` with the lists in the order `actual_read` gives them and
/// an absent `duplicates` as none.
fn expected_read(expected: &Value) -> Value {
    let list = |k: &str| expected.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let mut skipped = list("skipped");
    by_key(&mut skipped, "cipher");
    let mut uninspectable = list("uninspectable");
    uninspectable.sort_by_key(Value::to_string);
    json!({
        "items": list("items"),
        "skipped": skipped,
        "uninspectable": uninspectable,
        "duplicates": list("duplicates"),
    })
}

// --- writes ------------------------------------------------------------------

/// How a write ended: the requests sent, or an error.
enum Outcome {
    Requests(Vec<Value>),
    Error(String),
}

/// The vectors' write outcome for a `WriteError`. `Gone` and `Unmarked`
/// mean bwss gives up on the op (`runner::write_failure` maps them to
/// `Failure::Gone`): nothing more is sent.
fn write_error(e: WriteError) -> Outcome {
    match e {
        WriteError::Conflict => Outcome::Error("value-source-changed".into()),
        WriteError::TooLarge => Outcome::Error("too-long".into()),
        WriteError::NotesTaken => Outcome::Error("notes-hold-user-text".into()),
        WriteError::Gone | WriteError::Unmarked => Outcome::Requests(Vec::new()),
        WriteError::Uninspectable(why) => Outcome::Error(format!("(uninspectable: {why})")),
        WriteError::Crypto(e) => Outcome::Error(format!("(crypto: {e})")),
    }
}

fn decrypt(key: &SymmetricKey, v: Option<&Value>, what: &str) -> Result<Value, String> {
    match v {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(s)) if s.is_empty() => Ok(json!("")),
        Some(Value::String(s)) => {
            key.decrypt_str(s).map(|t| json!(t.as_str())).map_err(|e| format!("request {what} does not decrypt: {e}"))
        }
        Some(other) => Err(format!("request {what} is not a string: {other}")),
    }
}

fn is_extra(key: &str) -> bool {
    key.strip_prefix('x').is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// The canonical write body (vectors README) of a request bwss would send.
fn canonical(
    method: &str,
    cipher: Option<&str>,
    body: &Map<String, Value>,
    user: &SymmetricKey,
) -> Result<Value, String> {
    let whole = Value::Object(body.clone());
    let key = item_key(&whole, user).map_err(|e| format!("request item key does not unwrap: {e}"))?;
    let login = match body.get("login") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Object(l)) => {
            let uris = match l.get("uris") {
                Some(Value::Array(a)) => {
                    Value::Array(a.iter().map(|u| decrypt(&key, u.get("uri"), "uri")).collect::<Result<_, _>>()?)
                }
                None | Some(Value::Null) => Value::Null,
                Some(other) => return Err(format!("request uris: {other}")),
            };
            let history = body
                .get("passwordHistory")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|h| decrypt(&key, h.get("password"), "passwordHistory"))
                .collect::<Result<Vec<_>, _>>()?;
            json!({
                "username": decrypt(&key, l.get("username"), "username")?,
                "password": decrypt(&key, l.get("password"), "password")?,
                "uris": uris,
                "totp": decrypt(&key, l.get("totp"), "totp")?,
                "passwordHistory": history,
            })
        }
        Some(other) => return Err(format!("request login: {other}")),
    };
    let fields = body
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|f| {
            Ok(json!({
                "name": decrypt(&key, f.get("name"), "field name")?,
                "value": decrypt(&key, f.get("value"), "field value")?,
                "type": f.get("type").cloned().unwrap_or(Value::Null),
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let extra: Map<String, Value> =
        body.iter().filter(|(k, _)| is_extra(k)).map(|(k, v)| (k.clone(), v.clone())).collect();
    let plain = |k: &str| body.get(k).cloned().unwrap_or(Value::Null);
    Ok(json!({
        "method": method,
        "cipher": cipher,
        "type": plain("type"),
        "name": decrypt(&key, body.get("name"), "name")?,
        "notes": decrypt(&key, body.get("notes"), "notes")?,
        "login": login,
        "fields": fields,
        "organizationId": plain("organizationId"),
        "folderId": plain("folderId"),
        // A create body has none; the server reads that as null.
        "lastKnownRevisionDate": plain("lastKnownRevisionDate"),
        "hasItemKey": body.get("key").and_then(Value::as_str).is_some_and(|k| !k.is_empty()),
        "extra": extra,
    }))
}

/// The tool-defined parts of a create (vectors README, R16): `name`, and
/// every `bwss:*` field other than `bwss:id` and `bwss:password`.
fn without_tool_defined(mut requests: Vec<Value>) -> Vec<Value> {
    for r in requests.iter_mut().filter(|r| r.get("method") == Some(&json!("POST"))) {
        let Some(o) = r.as_object_mut() else { continue };
        o.remove("name");
        if let Some(Value::Array(fields)) = o.get_mut("fields") {
            fields.retain(|f| {
                let name = f.get("name").and_then(Value::as_str).unwrap_or_default();
                !name.starts_with("bwss:") || name == "bwss:id" || name == "bwss:password"
            });
        }
    }
    requests
}

fn put(cid: &str, body: &Map<String, Value>, keys: &Keys) -> Result<Value, String> {
    canonical("PUT", Some(cid), body, &keys.user)
}

/// `runner::plan_put` for a change of the value alone.
fn value_patch(old: &crate::bw::scan::MarkedItem, secret: Vec<u8>) -> Patch {
    let value = if secret.as_slice() == old.item.secret.as_slice() {
        ValueChange::Keep
    } else {
        ValueChange::Set { source: old.source, secret, base_mark: old.mark, owned: false }
    };
    Patch {
        id: old.item.id.clone(),
        base_revision: old.revision_date.clone(),
        set: Vec::new(),
        remove: Vec::new(),
        acl_add: Vec::new(),
        value,
        cipher_id: Some(old.cipher_id.clone()),
    }
}

fn find_cipher<'a>(ciphers: &'a [Value], cid: &str) -> Result<&'a Value, String> {
    ciphers.iter().find(|c| c.get("id").and_then(Value::as_str) == Some(cid)).ok_or_else(|| format!("no cipher {cid}"))
}

/// `runner::run_patch`: apply the patch to the copy read; when the server
/// rejects it as out of date, apply it again to the fresh copy.
fn run_set_value(ciphers: &[Value], fresh: Option<Value>, op: &Value, keys: &Keys) -> Result<Outcome, String> {
    let id = op.get("id").and_then(Value::as_str).ok_or("operation has no id")?;
    let secret = operation_secret(op.get("value").and_then(Value::as_str).ok_or("operation has no value")?)?;
    let built = build(&json!({ "ciphers": ciphers }), keys, None);
    let old = built.marked.get(id).ok_or_else(|| format!("bwss reads no item {id}"))?;
    let patch = value_patch(old, secret);
    if matches!(patch.value, ValueChange::Keep) {
        // `runner::is_empty`: nothing to send.
        return Ok(Outcome::Requests(Vec::new()));
    }
    let cipher = find_cipher(ciphers, &old.cipher_id)?;
    let body = match apply(cipher, &patch, keys) {
        Ok(body) => body,
        Err(e) => return Ok(write_error(e)),
    };
    let (cid, body) = match fresh {
        None => (old.cipher_id.clone(), body),
        Some(fresh) => {
            let cid = fresh.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
            match apply(&fresh, &patch, keys) {
                Ok(body) => (cid, body),
                Err(e) => return Ok(write_error(e)),
            }
        }
    };
    Ok(Outcome::Requests(vec![put(&cid, &body, keys)?]))
}

/// `runner::run_create`, with the item the daemon builds for a new secret.
fn run_create(ciphers: &[Value], op: &Value, keys: &Keys) -> Result<Outcome, String> {
    let id = op.get("id").and_then(Value::as_str).ok_or("operation has no id")?;
    let secret = operation_secret(op.get("value").and_then(Value::as_str).ok_or("operation has no value")?)?;
    let built = build(&json!({ "ciphers": ciphers }), keys, None);
    if built.marked.contains_key(id) {
        // Accepted before: never created twice.
        return Ok(Outcome::Requests(Vec::new()));
    }
    let item = ItemData {
        id: id.to_owned(),
        collection: LOGIN_COLLECTION.to_owned(),
        label: id.to_owned(),
        attributes: Attributes::new(),
        secret: Zeroizing::new(secret),
        content_type: "text/plain".to_owned(),
        created: now(),
        modified: 0,
        acl: Vec::new(),
    };
    let folder = op.get("folderId").and_then(Value::as_str);
    match new_note(&item, folder, keys) {
        Ok(body) => Ok(Outcome::Requests(vec![canonical("POST", None, &body, &keys.user)?])),
        Err(e) => Ok(write_error(e)),
    }
}

/// `runner::run_delete`: strip and save; with `fresh`, the save is out of
/// date and the strip starts over on the fresh copy. Then trash only what
/// the server returned (taken to be the body as sent) shows to be bwss's.
fn run_delete(ciphers: &[Value], fresh: Option<Value>, op: &Value, keys: &Keys) -> Result<Outcome, String> {
    let id = op.get("id").and_then(Value::as_str).ok_or("operation has no id")?;
    let built = build(&json!({ "ciphers": ciphers }), keys, None);
    let Some(old) = built.marked.get(id) else { return Ok(Outcome::Requests(Vec::new())) };
    let first = find_cipher(ciphers, &old.cipher_id)?.clone();
    let mut attempts = vec![first];
    attempts.extend(fresh);
    let last = attempts.len() - 1;
    for (n, cipher) in attempts.iter().enumerate() {
        match scan(cipher, keys) {
            Scan::Marked(m) if m.item.id == id => {}
            Scan::Uninspectable(why) => return Ok(Outcome::Error(format!("(uninspectable: {why})"))),
            _ => return Ok(Outcome::Requests(Vec::new())),
        }
        let cid = cipher.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
        let body = match strip(cipher, keys) {
            Ok(body) => body,
            Err(e) => return Ok(write_error(e)),
        };
        if n < last {
            continue;
        }
        let mut requests = vec![put(&cid, &body, keys)?];
        // Foreign content, or a body that cannot be inspected: kept, not trashed.
        if let Ok(false) = has_foreign_content(&Value::Object(body), keys) {
            requests.push(json!({ "method": "trash", "cipher": cid }));
        }
        return Ok(Outcome::Requests(requests));
    }
    Ok(Outcome::Requests(Vec::new()))
}

fn actual_write(ciphers: &[Value], op: &Value, keys: &Keys) -> Result<Value, String> {
    let fresh = op.get("fresh").cloned().map(normalize_keys);
    let outcome = match op.get("kind").and_then(Value::as_str) {
        Some("set-value") => run_set_value(ciphers, fresh, op, keys)?,
        Some("create") => run_create(ciphers, op, keys)?,
        Some("delete") => run_delete(ciphers, fresh, op, keys)?,
        other => return Err(format!("unknown operation kind {other:?}")),
    };
    Ok(match outcome {
        Outcome::Requests(r) => json!({ "requests": without_tool_defined(r) }),
        Outcome::Error(e) => json!({ "error": e }),
    })
}

fn expected_write(expected: &Value) -> Value {
    match expected.get("requests").and_then(Value::as_array) {
        Some(r) => json!({ "requests": without_tool_defined(r.clone()) }),
        None => expected.clone(),
    }
}

// --- the runner --------------------------------------------------------------

fn mismatch(what: &str, actual: &Value, expected: &Value) -> String {
    let pretty = |v: &Value| serde_json::to_string_pretty(v).unwrap_or_default();
    format!("{what} differs\n  bwss:     {}\n  expected: {}", pretty(actual), pretty(expected))
}

/// Runs one vector; `Err` says how bwss differs from the expectation.
fn run(dir: &Path, v: &Value, accounts: &mut HashMap<String, Keys>) -> Result<(), String> {
    let account = v.get("account").and_then(Value::as_str).ok_or("no account")?;
    let keys = accounts.entry(account.to_owned()).or_insert_with(|| account_keys(dir, account));
    let ciphers = server_ciphers(v);
    let expect = v.get("expect").ok_or("no expect")?;
    if expect.get("plan").is_some() {
        return Err("a plan expectation, but bwss has no sync planner".into());
    }
    if let Some(expected) = expect.get("read") {
        let (actual, expected) = (actual_read(&ciphers, keys, expected), expected_read(expected));
        if actual != expected {
            return Err(mismatch("read", &actual, &expected));
        }
    }
    if let Some(expected) = expect.get("write") {
        let op = v.get("operation").ok_or("a write expectation with no operation")?;
        let (actual, expected) = (actual_write(&ciphers, op, keys)?, expected_write(expected));
        if actual != expected {
            return Err(mismatch("write", &actual, &expected));
        }
    }
    Ok(())
}

/// Runs every vector whose id starts with `kind/` and checks the failures
/// against the expected-failures list.
fn run_kind(kind: &str) {
    let dir = vectors_dir();
    let prefix = format!("{kind}/");
    let listed: BTreeMap<String, String> =
        expected_failures().into_iter().filter(|(id, _)| id.starts_with(&prefix)).collect();
    let all = scenarios(&dir);
    let vectors: Vec<&(String, Value)> = all.iter().filter(|(id, _)| id.starts_with(&prefix)).collect();
    assert!(!vectors.is_empty(), "no {kind} vectors under {}", dir.display());

    let mut accounts = HashMap::new();
    let mut failed = BTreeSet::new();
    let mut report = Vec::new();
    for (id, v) in &vectors {
        match (run(&dir, v, &mut accounts), listed.get(id)) {
            (Ok(()), None) => report.push(format!("pass             {id}")),
            (Ok(()), Some(_)) => report.push(format!("LISTED BUT PASSES {id}")),
            (Err(why), Some(_)) => {
                failed.insert(id.clone());
                report.push(format!("expected fail    {id}: {why}"));
            }
            (Err(why), None) => {
                failed.insert(id.clone());
                report.push(format!("UNEXPECTED FAIL  {id}: {why}"));
            }
        }
    }
    let known: BTreeSet<&String> = vectors.iter().map(|(id, _)| id).collect();
    let unknown: Vec<&String> = listed.keys().filter(|id| !known.contains(id)).collect();
    let listed_ids: BTreeSet<String> = listed.keys().cloned().collect();
    let unexpected = failed.difference(&listed_ids).count();
    let passing_listed = listed_ids.difference(&failed).count();
    let expected_fail = failed.intersection(&listed_ids).count();
    println!("{}", report.join("\n"));
    let totals = format!(
        "{kind}: {} vectors, {} pass, {expected_fail} expected-fail, {unexpected} unexpected-fail, \
         {passing_listed} listed but passing, unknown listed ids {unknown:?}",
        vectors.len(),
        vectors.len() - failed.len(),
    );
    println!("{totals}");
    assert!(unexpected == 0 && passing_listed == 0 && unknown.is_empty(), "{totals}");
}

#[test]
fn read_scenarios() {
    run_kind("read");
}

#[test]
fn write_scenarios() {
    run_kind("write");
}

/// The generator emits no sync scenarios for bwss, which has no planner;
/// any that appear would otherwise go unrun.
#[test]
fn only_read_and_write_scenarios() {
    let dir = vectors_dir();
    let others: Vec<String> = scenarios(&dir)
        .into_iter()
        .map(|(id, _)| id)
        .filter(|id| !id.starts_with("read/") && !id.starts_with("write/"))
        .collect();
    assert!(others.is_empty(), "bwss vectors of an unrun kind: {others:?}");
}

#[test]
fn reasons_map_to_shared_codes() {
    for (why, code) in [
        ("c1: item type 3 is not supported", "wrong-type"),
        ("c1: unknown bwss:location", "unknown-location"),
        ("c1: unknown bwss:encoding", "unknown-encoding"),
        ("c1: bwss:encoding=base64 on a value bwss does not own", "encoding-on-user-source"),
        ("c1: _collections is reserved", "reserved-id"),
        ("c1: value is not valid base64", "c1: value is not valid base64"),
    ] {
        assert_eq!(reason_code(why), code, "{why}");
    }
}
