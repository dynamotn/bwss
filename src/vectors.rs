//! The dybw conformance vectors (`dybw-core/vectors/generated/bwss/`), run
//! against bwss's glue over the core: the snapshot build (labels, the
//! registry skip, derived attributes off) over the core's scan, and bwss's
//! write plan over the core's writer.
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
use dybw_core::crypto::{
    Cbor, EnvelopeNamespace, MarkScheme, Marker, SymmetricKey as CoreKey, open_envelope, parse_cek, unwrap_signing_key,
    verify_security_state,
};
use dybw_core::ports::{Http, HttpRequest, HttpResponse, Method, PortError};
use dybw_core::sync::{self, Op, SyncWriteError};
use dybw_core::vault::fields as core_fields;
use dybw_core::vault::write::{HistoryAnswer, Patch, ValueChange, WriteError, WriteRecord};
use dybw_core::vault::{Keys as CoreKeys, Namespace, Organizations, Scan, SkipReason, ValueSource, scan};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::backend::bitwarden::{Bindings, Built};
use crate::backend::ops::new_item_of;
use crate::backend::runner::plan_put;
use crate::core_ports::clock::SystemClock;
use crate::core_ports::random::OsRandom;
use crate::fields::{DERIVED, F_ACL};
use crate::model::{Attributes, ItemData, LOGIN_COLLECTION, now};

/// bwss's snapshot build over the core's scan, with derived attributes off
/// (ADR 0015) and the device's bindings (ADR 0019).
fn build(sync: &Value, keys: &CoreKeys, bound: &Bindings) -> Built {
    crate::backend::bitwarden::build(sync, keys, None, &mut Default::default(), bound, false)
}

/// The vector's device bindings (`device.base`, ADR 0019): `bwss:id` to cipher id.
fn bindings(v: &Value) -> Bindings {
    let base = v.pointer("/device/base").and_then(Value::as_object).into_iter().flatten();
    base.filter_map(|(id, e)| Some((id.clone(), e.get("cipher")?.as_str()?.to_owned()))).collect()
}

const NAMESPACE: &str = "bwss";
const NOT_FOUND: &str = "conformance vectors not found: set DYBW_VECTORS_DIR";
const EXPECTED_FAILURES: &str = "tests/vectors-expected-failures.txt";

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
fn actual_read(ciphers: &[Value], keys: &CoreKeys, bound: &Bindings, expected: &Value) -> Value {
    let built = build(&json!({ "ciphers": ciphers }), keys, bound);
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
                "source": m.source.code(),
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
        built.skipped.iter().map(|(cid, why, _)| json!({ "cipher": cid, "reason": why.code() })).collect();
    by_key(&mut skipped, "cipher");
    // bwss holds these (`snapshot.held`) without saying why; the core's scan names them.
    let mut uninspectable: Vec<String> = ciphers
        .iter()
        .filter(|c| matches!(scan(c, &Namespace::BWSS, keys, &Organizations::None), Scan::Uninspectable(_)))
        .filter_map(|c| c.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    uninspectable.sort();
    let duplicates: Vec<Value> = built
        .duplicates
        .iter()
        .map(|d| {
            let mut out = json!({ "id": d.id, "kept": d.kept, "left": d.left });
            if let (true, Some(o)) = (d.bound_kept, out.as_object_mut()) {
                o.insert("boundKept".into(), json!(true));
            }
            out
        })
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

/// A decoded CBOR item as JSON: a byte string is its base64 text and a map
/// key is its text, which is all a blob needs.
fn cbor_json(c: &Cbor) -> Result<Value, String> {
    Ok(match c {
        Cbor::Uint(n) => json!(n),
        Cbor::Nint(n) => json!(-1 - i64::try_from(*n).map_err(|_| "CBOR integer")?),
        Cbor::Bytes(b) => json!(B64.encode(b.as_slice())),
        Cbor::Text(t) => json!(t.as_str()),
        Cbor::Bool(b) => json!(b),
        Cbor::Null => Value::Null,
        Cbor::Array(a) => Value::Array(a.iter().map(cbor_json).collect::<Result<_, _>>()?),
        Cbor::Map(m) => {
            let mut map = Map::new();
            for (k, v) in m {
                let key = match cbor_json(k)? {
                    Value::String(s) => s,
                    Value::Number(n) => n.to_string(),
                    _ => return Err("CBOR map key".into()),
                };
                map.insert(key, cbor_json(v)?);
            }
            Value::Object(map)
        }
    })
}

/// The sealed content (`CipherBlobV1`) of a blob request (ADR 0021): `data`
/// is the sealed blob's JSON text, its content key wrapped under `key`.
fn open_blob(data: &str, key: &CoreKey) -> Result<Value, String> {
    let sealed: Value = serde_json::from_str(data).map_err(|_| "blob data is not JSON")?;
    if sealed.get("format_version") != Some(&json!(1)) {
        return Err("blob format_version is not 1".into());
    }
    let wrapped = sealed.get("wrapped_cek").and_then(Value::as_str).ok_or("blob wrapped_cek is missing")?;
    let cek = key.decrypt(wrapped).map_err(|e| format!("blob wrapped_cek: {e}"))?;
    let cek = parse_cek(&cek).map_err(|e| format!("blob content key: {e}"))?;
    let text = sealed.get("envelope").and_then(Value::as_str).ok_or("blob envelope is missing")?;
    let envelope = B64.decode(text).map_err(|_| "blob envelope is not base64")?;
    let opened =
        open_envelope(&cek, &envelope, EnvelopeNamespace::VaultItem).map_err(|e| format!("blob envelope: {e}"))?;
    let content = cbor_json(&opened)?;
    if content.get("version") != Some(&json!("1")) {
        return Err("blob content version is not 1".into());
    }
    content.get("content").cloned().ok_or_else(|| "blob has no content".into())
}

/// The canonical `name`, `notes`, `login` and `fields` of a blob's content.
fn blob_parts(content: &Value) -> (Value, Value, Value, Value) {
    let get = |v: &Value, k: &str| v.get(k).cloned().unwrap_or(Value::Null);
    let list = |v: &Value, k: &str| v.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let type_data = content.get("typeData").cloned().unwrap_or(Value::Null);
    let login = if type_data.get("type") == Some(&json!("login")) {
        json!({
            "username": get(&type_data, "username"),
            "password": get(&type_data, "password"),
            "uris": list(&type_data, "uris").iter().map(|u| get(u, "uri")).collect::<Vec<_>>(),
            "totp": get(&type_data, "totp"),
            "passwordHistory": list(content, "passwordHistory").iter().map(|h| get(h, "password")).collect::<Vec<_>>(),
        })
    } else {
        Value::Null
    };
    let fields = list(content, "fields")
        .iter()
        .map(|f| json!({ "name": get(f, "name"), "value": get(f, "value"), "type": get(f, "type") }))
        .collect::<Vec<_>>();
    (get(content, "name"), get(content, "notes"), login, json!(fields))
}

/// The canonical write body (vectors README) of a request bwss sent; a blob
/// is opened and read as the README's `blob` request.
fn canonical(method: &str, cipher: Option<&str>, body: &Map<String, Value>, user: &CoreKey) -> Result<Value, String> {
    let whole = Value::Object(body.clone());
    let key = core_fields::item_key(&whole, user).map_err(|e| format!("request item key does not unwrap: {e}"))?;
    let blob = match body.get("data") {
        None | Some(Value::Null) => None,
        Some(Value::String(data)) => Some(open_blob(data, &key)?),
        Some(other) => return Err(format!("request data: {other}")),
    };
    let (name, notes, login, fields) = match &blob {
        Some(content) => blob_parts(content),
        None => plain_parts(body, &key)?,
    };
    let extra: Map<String, Value> =
        body.iter().filter(|(k, _)| is_extra(k)).map(|(k, v)| (k.clone(), v.clone())).collect();
    let plain = |k: &str| body.get(k).cloned().unwrap_or(Value::Null);
    let mut request = json!({
        "method": method,
        "cipher": cipher,
        "type": plain("type"),
        "name": name,
        "notes": notes,
        "login": login,
        "fields": fields,
        "organizationId": plain("organizationId"),
        "folderId": plain("folderId"),
        // A create body has none; the server reads that as null.
        "lastKnownRevisionDate": plain("lastKnownRevisionDate"),
        "hasItemKey": body.get("key").and_then(Value::as_str).is_some_and(|k| !k.is_empty()),
        "extra": extra,
    });
    if let (Some(content), Some(o)) = (&blob, request.as_object_mut()) {
        o.insert("blob".into(), json!(true));
        // The sealed content's unknown keys, listed only when there are any (README, canonical body).
        let unknown: Map<String, Value> = content
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(k, _)| is_extra(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if !unknown.is_empty() {
            o.insert("blobExtra".into(), Value::Object(unknown));
        }
    }
    Ok(request)
}

/// The canonical `name`, `notes`, `login` and `fields` of a request that is
/// not a blob, decrypted with the item key.
fn plain_parts(body: &Map<String, Value>, key: &CoreKey) -> Result<(Value, Value, Value, Value), String> {
    let login = match body.get("login") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Object(l)) => {
            let uris = match l.get("uris") {
                Some(Value::Array(a)) => {
                    Value::Array(a.iter().map(|u| decrypt(key, u.get("uri"), "uri")).collect::<Result<_, _>>()?)
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
                .map(|h| decrypt(key, h.get("password"), "passwordHistory"))
                .collect::<Result<Vec<_>, _>>()?;
            json!({
                "username": decrypt(key, l.get("username"), "username")?,
                "password": decrypt(key, l.get("password"), "password")?,
                "uris": uris,
                "totp": decrypt(key, l.get("totp"), "totp")?,
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
                "name": decrypt(key, f.get("name"), "field name")?,
                "value": decrypt(key, f.get("value"), "field value")?,
                "type": f.get("type").cloned().unwrap_or(Value::Null),
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let name = decrypt(key, body.get("name"), "name")?;
    Ok((name, decrypt(key, body.get("notes"), "notes")?, login, Value::Array(fields)))
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

/// A value-only patch of the cipher that carries `id` but was skipped for
/// `dybw:requires` (ADR 0020). bwss never serves such an item, so no app
/// holds a copy to write; the vector checks that the core refuses one that
/// is written anyway, as from a stale copy.
fn stale_patch(built: &Built, ciphers: &[Value], keys: &CoreKeys, id: &str, secret: Vec<u8>) -> Option<Op> {
    let carries = |c: &Value| -> Option<bool> {
        let key = core_fields::item_key(c, &keys.user).ok()?;
        let names = core_fields::field_names(c, &key).ok()?;
        let at = core_fields::first_index(&names, crate::fields::F_ID)?;
        Some(core_fields::field_value(c, at, &key).ok()?.trim() == id)
    };
    let held = |c: &&Value| {
        let cid = c.get("id").and_then(Value::as_str).unwrap_or_default();
        built.skipped.iter().any(|(s, why, _)| s == cid && *why == SkipReason::NewerFormat)
    };
    let cipher = ciphers.iter().filter(held).find(|c| carries(c) == Some(true))?;
    Some(Op::Patch(Patch {
        id: id.to_owned(),
        cipher_id: cipher.get("id").and_then(Value::as_str).map(str::to_owned),
        organization_id: None,
        base_revision: String::new(),
        set: Vec::new(),
        remove: Vec::new(),
        append_lines: Vec::new(),
        value: ValueChange::Set {
            source: ValueSource::Field,
            secret: Zeroizing::new(secret),
            base_mark: [0; 32],
            owned: false,
        },
        answer: None,
    }))
}

/// The op the daemon's write turns into through bwss's glue: `plan_put` of
/// the item with its new value and ACL lines, or `new_item_of` a new one.
fn planned(built: &Built, ciphers: &[Value], keys: &CoreKeys, op: &Value, id: &str) -> Result<Option<Op>, String> {
    let secret = operation_secret(op.get("value").and_then(Value::as_str).ok_or("operation has no value")?)?;
    match op.get("kind").and_then(Value::as_str) {
        Some("set-value") => {
            let Some(old) = built.marked.get(id) else {
                return stale_patch(built, ciphers, keys, id, secret)
                    .map(Some)
                    .ok_or_else(|| format!("bwss reads no item {id}"));
            };
            let mut new = old.item.clone();
            new.secret = Zeroizing::new(secret);
            for add in op.get("appendLines").and_then(Value::as_array).into_iter().flatten() {
                if add.get("name").and_then(Value::as_str) != Some(F_ACL) {
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
    let built = build(&sync, keys, &bindings(v));
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
        _ => match planned(&built, ciphers, keys, op, id)? {
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
    if let Some(expected) = expect.get("plan") {
        // bwss has no sync planner: a sync rebuilds the snapshot and sends nothing,
        // so its plan is always empty; a vector that plans an action fails here.
        let actual = json!([]);
        if &actual != expected {
            return Err(mismatch("plan", &actual, expected));
        }
    }
    if let Some(expected) = expect.get("read") {
        let keys = core_account_keys(dir, account)?;
        let (actual, expected) = (actual_read(&ciphers, &keys, &bindings(v), expected), expected_read(expected));
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

#[test]
fn sync_scenarios() {
    run_kind("sync");
}

/// Every kind of scenario is run: one of a new kind fails here until bwss
/// runs it.
#[test]
fn only_read_write_and_sync_scenarios() {
    let others: Vec<String> = scenarios(&vectors_dir())
        .into_iter()
        .map(|(id, _)| id)
        .filter(|id| !["read/", "write/", "sync/"].iter().any(|k| id.starts_with(k)))
        .collect();
    assert!(others.is_empty(), "bwss vectors of an unrun kind: {others:?}");
}
