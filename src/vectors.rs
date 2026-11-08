//! The dybw conformance vectors (`dybw-core/vectors/generated/bwss/`), run
//! against bwss's real read code and its write glue over the core's writer.
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

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use dybw_core::api::{ApiKey, Client, DeviceInfo, normalize_keys, origin_of, resolve_server_urls};
use dybw_core::crypto::{MarkScheme, Marker, SymmetricKey as CoreKey, unwrap_signing_key, verify_security_state};
use dybw_core::ports::{Http, HttpRequest, HttpResponse, Method, PortError};
use dybw_core::sync::{self, Op, SyncWriteError};
use dybw_core::vault::fields as core_fields;
use dybw_core::vault::write::{HistoryAnswer, Patch, WriteError, WriteRecord};
use dybw_core::vault::{Keys as CoreKeys, Namespace};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::backend::bitwarden::Built;
use crate::backend::ops::new_item_of;
use crate::backend::runner::plan_put;
use crate::bw::crypto::SymmetricKey;
use crate::bw::scan::{Keys, Scan, ValueSource, scan};
use crate::core_ports::clock::SystemClock;
use crate::core_ports::random::OsRandom;
use crate::model::{Attributes, ItemData, LOGIN_COLLECTION, now};

/// bwss's snapshot build over the core's scan.
fn build(sync: &Value, core: &CoreKeys, previous: Option<&Built>) -> Built {
    let bound = previous.map(|p| p.bound.clone()).unwrap_or_default();
    crate::backend::bitwarden::build(sync, core, previous, &mut Default::default(), &bound)
}

/// The core's keys for bwss's own legacy keys.
// shortcut: the read side still takes bwss's own keys; B9 moves it to the core's.
fn core_of(keys: &Keys) -> Option<CoreKeys> {
    let user = CoreKey::from_bytes(&keys.user.to_bytes()).ok()?;
    Some(CoreKeys { marker: Marker::new(&user, MarkScheme::Bwss), user, orgs: BTreeMap::new(), security_version: 0 })
}

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
    ("value is not valid base64", "invalid-base64"),
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
/// `Err` for a user key bwss cannot hold (a COSE key): the vectors of that account fail, they do not abort the run.
fn account_keys(dir: &Path, name: &str) -> Result<Keys, String> {
    let account = read_json(&dir.join("accounts").join(format!("{name}.json")));
    let raw = account.get("userKey").and_then(Value::as_str).unwrap_or_else(|| panic!("{name}: no userKey"));
    let bytes = Zeroizing::new(B64.decode(raw).unwrap_or_else(|e| panic!("{name}: userKey: {e}")));
    let user = SymmetricKey::from_bytes(&bytes).map_err(|e| format!("{name}: userKey: {e}"))?;
    Ok(Keys { mark: user.derive("value-mark"), user })
}

/// The keys the core opens for account `name`: its user key (legacy or COSE)
/// and the version of its signed security state, 0 without one.
fn core_account_keys(dir: &Path, name: &str) -> Result<CoreKeys, String> {
    let account = read_json(&dir.join("accounts").join(format!("{name}.json")));
    let raw = account.get("userKey").and_then(Value::as_str).unwrap_or_else(|| panic!("{name}: no userKey"));
    let bytes = Zeroizing::new(B64.decode(raw).unwrap_or_else(|e| panic!("{name}: userKey: {e}")));
    let user = CoreKey::from_bytes(&bytes).map_err(|e| format!("{name}: userKey: {e}"))?;
    let security_version = match account.pointer("/profile/accountKeys") {
        Some(keys) => {
            let text = |p: &str| keys.pointer(p).and_then(Value::as_str).unwrap_or_default();
            let signing = unwrap_signing_key(&user, text("/signatureKeyPair/wrappedSigningKey"))
                .map_err(|e| format!("{name}: wrappedSigningKey: {e}"))?;
            verify_security_state(&signing, text("/securityState/securityState"))
                .map_err(|e| format!("{name}: securityState: {e}"))?
        }
        None => 0,
    };
    Ok(CoreKeys { marker: Marker::new(&user, MarkScheme::Bwss), user, orgs: BTreeMap::new(), security_version })
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
    let built = core_of(keys).map(|core| build(&json!({ "ciphers": ciphers }), &core, None)).unwrap_or_default();
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

const SERVER: &str = "https://vectors.invalid";
/// What the server answers to every write (vectors README, "Delete").
const SERVER_REVISION: &str = "2026-12-01T00:00:00.000Z";
const OUT_OF_DATE: &str = "The client copy of this cipher is out of date. Resubmit with the current revision date.";

/// A fake server behind the core's client: it serves the vector's ciphers,
/// accepts every write and keeps it; with `fresh`, the first update is
/// rejected as out of date and `fresh` is served from then on.
#[derive(Clone, Default)]
struct Server(Rc<RefCell<ServerState>>);

/// `(method, cipher, body)` of a write the server accepted.
type Sent = (&'static str, Option<String>, Option<Map<String, Value>>);

#[derive(Default)]
struct ServerState {
    ciphers: Vec<Value>,
    fresh: Option<Value>,
    rejected: u32,
    /// `(method, cipher, body)` of each accepted write.
    sent: Vec<Sent>,
}

fn answer(status: u16, body: &Value) -> Result<HttpResponse, PortError> {
    Ok(HttpResponse { status, body: Zeroizing::new(body.to_string().into_bytes()) })
}

/// The body as sent, plus the server's `id` and `revisionDate`.
fn reply(body: &Map<String, Value>, id: &str) -> Value {
    let mut out = body.clone();
    out.insert("id".into(), json!(id));
    out.insert("revisionDate".into(), json!(SERVER_REVISION));
    Value::Object(out)
}

impl Http for Server {
    fn refuses_redirects(&self) -> bool {
        true
    }

    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, PortError> {
        let path = req.url.strip_prefix(SERVER).unwrap_or(&req.url);
        let path = path.split('?').next().unwrap_or(path);
        let body: Option<Map<String, Value>> = req
            .body
            .as_deref()
            .and_then(|b| serde_json::from_slice::<Value>(b).ok())
            .and_then(|v| v.as_object().cloned());
        let mut s = self.0.borrow_mut();
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        match (req.method, segments.as_slice()) {
            (Method::Post, ["identity", "connect", "token"]) => {
                answer(200, &json!({ "access_token": "vectors", "expires_in": 3600 }))
            }
            (Method::Get, ["api", "sync"]) => {
                answer(200, &json!({ "profile": { "id": "vectors-user", "key": "k" }, "ciphers": s.ciphers }))
            }
            (Method::Get, ["api", "ciphers", id]) => {
                match s.ciphers.iter().find(|c| c.get("id").and_then(Value::as_str) == Some(*id)) {
                    Some(c) => answer(200, c),
                    None => answer(404, &json!({})),
                }
            }
            (Method::Post, ["api", "ciphers"]) => {
                let body = body.unwrap_or_default();
                let out = reply(&body, "cipher-created");
                s.sent.push(("POST", None, Some(body)));
                answer(200, &out)
            }
            (Method::Put, ["api", "ciphers", id, "delete"]) => {
                s.sent.push(("trash", Some((*id).to_owned()), None));
                answer(200, &json!({}))
            }
            (Method::Put, ["api", "ciphers", id]) => {
                if let Some(fresh) = s.fresh.take() {
                    s.rejected += 1;
                    s.ciphers.retain(|c| c.get("id").and_then(Value::as_str) != Some(*id));
                    s.ciphers.push(fresh);
                    return answer(400, &json!({ "message": OUT_OF_DATE }));
                }
                let body = body.unwrap_or_default();
                let out = reply(&body, id);
                s.sent.push(("PUT", Some((*id).to_owned()), Some(body)));
                answer(200, &out)
            }
            _ => answer(404, &json!({})),
        }
    }
}

fn decrypt(key: &CoreKey, v: Option<&Value>, what: &str) -> Result<Value, String> {
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

/// The canonical write body (vectors README) of a request bwss sent.
// shortcut: a blob request (`data`) is not decoded: the core keeps the blob codec private; B9 moves this adapter onto
// the core's vector runner.
fn canonical(method: &str, cipher: Option<&str>, body: &Map<String, Value>, user: &CoreKey) -> Result<Value, String> {
    if body.get("data").is_some_and(Value::is_string) {
        return Err("the request is a blob, which this adapter cannot decode".into());
    }
    let whole = Value::Object(body.clone());
    let key = core_fields::item_key(&whole, user).map_err(|e| format!("request item key does not unwrap: {e}"))?;
    let login = match body.get("login") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Object(l)) => {
            let uris = match l.get("uris") {
                Some(Value::Array(a)) => {
                    Value::Array(a.iter().map(|u| decrypt(&key, u.get("uri"), "uri")).collect::<Result<_, _>>()?)
                }
                // Absent and null read as [], like the plugin's adapter.
                None | Some(Value::Null) => Value::Array(Vec::new()),
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

/// This device's write record of `id` from the vector's `device.base` (ADR 0016).
fn record(v: &Value, id: &str, keys: &CoreKeys) -> WriteRecord {
    let Some(entry) = v.pointer(&format!("/device/base/{id}")) else { return WriteRecord::default() };
    let written = entry.get("written").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str);
    WriteRecord {
        written: written.map(|w| keys.marker.mark(id, w)).collect(),
        confirmed: entry.get("writeBackConfirmed").and_then(Value::as_bool).unwrap_or(false),
        cipher_id: None,
    }
}

/// The answer the vector gives to a question (README, `operation.answer`).
fn given(op: &Value) -> Option<HistoryAnswer> {
    match op.get("answer").and_then(Value::as_str) {
        None | Some("write-to-login") => Some(HistoryAnswer::WriteToLogin),
        Some("keep-separate") => Some(HistoryAnswer::KeepSeparate),
        _ => None,
    }
}

/// The op the daemon's write turns into through bwss's glue: `plan_put` of
/// the item with its new value and ACL lines, or `new_item_of` a new one.
fn planned(built: &Built, op: &Value, id: &str) -> Result<Option<Op>, String> {
    let secret = operation_secret(op.get("value").and_then(Value::as_str).ok_or("operation has no value")?)?;
    match op.get("kind").and_then(Value::as_str) {
        Some("set-value") => {
            let old = built.marked.get(id).ok_or_else(|| format!("bwss reads no item {id}"))?;
            let mut new = old.item.clone();
            new.secret = Zeroizing::new(secret);
            for add in op.get("appendLines").and_then(Value::as_array).into_iter().flatten() {
                if add.get("name").and_then(Value::as_str) != Some(crate::bw::fields::F_ACL) {
                    return Err("bwss appends lines to bwss:acl only".into());
                }
                new.acl.extend(
                    add.get("lines")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned),
                );
            }
            Ok(Some(plan_put(Some(old), &new)))
        }
        Some("create") => {
            if built.marked.contains_key(id) {
                // Accepted before: never created twice.
                return Ok(None);
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
            Ok(Some(Op::Create(new_item_of(&item, op.get("folderId").and_then(Value::as_str)))))
        }
        other => Err(format!("unknown operation kind {other:?}")),
    }
}

/// Runs the vector's operation through bwss's glue and the core's writer
/// against the fake server: the requests it sent, or what stopped it.
async fn written(v: &Value, ciphers: &[Value], op: &Value, keys: &CoreKeys) -> Result<Value, String> {
    let id = op.get("id").and_then(Value::as_str).ok_or("operation has no id")?;
    let server = Server::default();
    server.0.borrow_mut().ciphers = ciphers.to_vec();
    let urls = resolve_server_urls(SERVER).map_err(|e| e.to_string())?;
    let device = DeviceInfo {
        identifier: "vectors-device".into(),
        name: "bwss".into(),
        device_type: 8,
        client_name: "bwss".into(),
        client_version: "0".into(),
    };
    let key = ApiKey {
        origin: origin_of(&urls.identity).map_err(|e| e.to_string())?,
        client_id: "vectors".into(),
        client_secret: Zeroizing::new("vectors".into()),
    };
    let mut client = Client::new(server.clone(), SystemClock, urls, device).map_err(|e| e.to_string())?;
    client.login(&key).await.map_err(|e| e.to_string())?;
    let sync = client.sync().await.map_err(|e| e.to_string())?;
    let built = build(&sync, keys, None);
    let fresh = op.get("fresh").cloned().map(normalize_keys);
    server.0.borrow_mut().fresh.clone_from(&fresh);
    let ns = &Namespace::BWSS;
    let now = client.now_ms();
    let sent = match op.get("kind").and_then(Value::as_str) {
        Some("delete") => match built.marked.get(id) {
            None => Ok(()),
            Some(m) => {
                let cipher = ciphers.iter().find(|c| c.get("id").and_then(Value::as_str) == Some(&m.cipher_id));
                let cipher = cipher.ok_or_else(|| format!("no cipher {}", m.cipher_id))?;
                sync::delete(&mut client, ns, keys, &OsRandom, cipher, id).await.map(|_| ())
            }
        },
        _ => match planned(&built, op, id)? {
            None => Ok(()),
            Some(Op::Create(item)) => sync::create(&mut client, ns, keys, &OsRandom, &item).await.map(|_| ()),
            Some(Op::Patch(patch)) => {
                let cid = patch.cipher_id.clone().unwrap_or_default();
                let cipher = ciphers.iter().find(|c| c.get("id").and_then(Value::as_str) == Some(&cid));
                let cipher = cipher.ok_or_else(|| format!("no cipher {cid}"))?;
                let record = record(v, id, keys);
                // Asked first, as the daemon asks: the vector's answer then goes to the question the copy raised.
                match (sync::update(&mut client, ns, keys, &record, &OsRandom, now, cipher, &patch).await, given(op)) {
                    (Err(SyncWriteError::Write(WriteError::Ask(q))), Some(a)) => {
                        let patch = Patch { answer: Some((q, a)), ..patch };
                        sync::update(&mut client, ns, keys, &record, &OsRandom, now, cipher, &patch).await.map(|_| ())
                    }
                    (sent, _) => sent.map(|_| ()),
                }
            }
            Some(Op::Delete { .. }) => Err("a plan never deletes".to_owned())?,
        },
    };
    let state = server.0.borrow();
    if state.rejected != u32::from(fresh.is_some()) {
        return Err(format!("out-of-date rejections: {}", state.rejected));
    }
    let requests = || -> Result<Value, String> {
        let list = state
            .sent
            .iter()
            .map(|(method, cid, body)| match body {
                Some(body) => canonical(method, cid.as_deref(), body, &keys.user),
                None => Ok(json!({ "method": method, "cipher": cid })),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({ "requests": without_tool_defined(list) }))
    };
    match sent {
        Ok(()) => requests(),
        // After a refetch, a copy that lost its marker or was deleted means bwss gave up (§6.5).
        Err(SyncWriteError::Write(WriteError::Unmarked | WriteError::Gone)) if fresh.is_some() => requests(),
        Err(SyncWriteError::Write(WriteError::Ask(q))) => Ok(json!({ "question": q.code() })),
        Err(SyncWriteError::Write(e)) => {
            Ok(json!({ "error": e.code().map_or_else(|| format!("({e})"), str::to_owned) }))
        }
        Err(e) => Ok(json!({ "error": format!("({e})") })),
    }
}

fn actual_write(v: &Value, ciphers: &[Value], op: &Value, keys: &CoreKeys) -> Result<Value, String> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    runtime.block_on(written(v, ciphers, op, keys))
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
fn run(dir: &Path, v: &Value) -> Result<(), String> {
    let account = v.get("account").and_then(Value::as_str).ok_or("no account")?;
    let ciphers = server_ciphers(v);
    let expect = v.get("expect").ok_or("no expect")?;
    if expect.get("plan").is_some() {
        return Err("a plan expectation, but bwss has no sync planner".into());
    }
    if let Some(expected) = expect.get("read") {
        let keys = account_keys(dir, account)?;
        let (actual, expected) = (actual_read(&ciphers, &keys, expected), expected_read(expected));
        if actual != expected {
            return Err(mismatch("read", &actual, &expected));
        }
    }
    if let Some(expected) = expect.get("write") {
        let op = v.get("operation").ok_or("a write expectation with no operation")?;
        let keys = core_account_keys(dir, account)?;
        let (actual, expected) = (actual_write(v, &ciphers, op, &keys)?, expected_write(expected));
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

    let mut failed = BTreeSet::new();
    let mut report = Vec::new();
    for (id, v) in &vectors {
        match (run(&dir, v), listed.get(id)) {
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

/// bwss has no planner, so a sync scenario never runs: each one must be
/// listed as an expected failure, or it would otherwise go unrun.
#[test]
fn only_read_and_write_scenarios() {
    let dir = vectors_dir();
    let listed = expected_failures();
    let others: Vec<String> = scenarios(&dir)
        .into_iter()
        .map(|(id, _)| id)
        .filter(|id| !id.starts_with("read/") && !id.starts_with("write/") && !listed.contains_key(id))
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
        ("c1: value is not valid base64", "invalid-base64"),
    ] {
        assert_eq!(reason_code(why), code, "{why}");
    }
}
