//! The write path end to end, against an in-process fake Bitwarden server.

#![expect(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};

use futures_util::FutureExt as _;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::Backend;
use super::BackendError;
use super::bitwarden::{Bitwarden, BitwardenBackend};
use super::ops::{Loaded, QUEUE_FORMAT, Queue, new_item_of, read_formats, unseal};
use super::registry::Registry;
use super::runner::Effect;
use crate::config::{Config, Credentials, Paths};
use crate::core_ports::random::OsRandom;
use crate::model::{Attributes, ItemData, Snapshot};
use dybw_core::crypto::{KdfParams, MarkScheme, Marker, NativeArgon2, SymmetricKey, derive_master_key};
use dybw_core::ports::Storage;
use dybw_core::sync::Op;
use dybw_core::vault::fields::field_names;
use dybw_core::vault::write::{HistoryAnswer, HistoryQuestion, Patch, ValueChange, WriteRecord};
use dybw_core::vault::{Keys, Namespace, Organizations, Scan, scan};

const EMAIL: &str = "a@b.c";
const PASSWORD: &str = "pw";
const ITERATIONS: u32 = 5_000;
const REV: &str = "2026-01-01T00:00:00Z";

type Hook = Box<dyn FnOnce(&mut Value) + Send>;

/// A canned answer for the requests it matches, `times` times.
struct Fault {
    method: &'static str,
    /// Matches the path without its query.
    prefix: String,
    status: u16,
    reply: Option<Value>,
    times: usize,
}

struct Server {
    sync: Value,
    rev: u64,
    down: bool,
    /// Every item update fails with 503.
    fail_puts: bool,
    /// The next this many item updates find the cipher changed elsewhere.
    stale_puts: usize,
    requests: Vec<(String, String)>,
    /// Answers that replace the server's own, first match first.
    faults: Vec<Fault>,
    /// Run on the stored cipher right before the next PUT to it is handled:
    /// an edit made on another device.
    before_put: Option<Hook>,
    /// `(method, path)`: the server announces the request and waits until
    /// it is released.
    pause: Option<(String, String, mpsc::Sender<()>, mpsc::Receiver<()>)>,
}

impl Server {
    fn revision(&self) -> String {
        format!("2026-10-24T00:00:00.{:06}Z", self.rev)
    }

    fn find(&mut self, id: &str) -> Option<&mut Value> {
        self.sync["ciphers"].as_array_mut()?.iter_mut().find(|c| c["id"] == id)
    }

    fn store(&mut self, id: &str, mut body: Value) -> Value {
        self.rev += 1;
        let created = self.find(id).map_or(json!(REV), |c| c["creationDate"].clone());
        let o = body.as_object_mut().expect("an object body");
        o.remove("lastKnownRevisionDate");
        o.remove("encryptedFor");
        o.insert("id".into(), json!(id));
        o.insert("revisionDate".into(), json!(self.revision()));
        o.insert("creationDate".into(), created);
        o.insert("deletedDate".into(), Value::Null);
        o.insert("object".into(), json!("cipherDetails"));
        match self.find(id) {
            Some(c) => *c = body.clone(),
            None => {
                // A vault that never held a cipher may have no list yet.
                if !self.sync["ciphers"].is_array() {
                    self.sync["ciphers"] = json!([]);
                }
                self.sync["ciphers"].as_array_mut().expect("ciphers").push(body.clone());
            }
        }
        body
    }

    fn handle(&mut self, method: &str, path: &str, body: &[u8]) -> (u16, Option<Value>) {
        self.requests.push((method.to_owned(), path.to_owned()));
        if self.down {
            return (503, None);
        }
        let body: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let path = path.split('?').next().unwrap_or_default();
        if let Some(f) =
            self.faults.iter_mut().find(|f| f.times > 0 && f.method == method && path.starts_with(&f.prefix))
        {
            f.times -= 1;
            return (f.status, f.reply.clone());
        }
        match (method, path) {
            ("POST", "/identity/accounts/prelogin") => (200, Some(json!({ "kdf": 0, "kdfIterations": ITERATIONS }))),
            ("POST", "/identity/connect/token") => (200, Some(json!({ "access_token": "t", "expires_in": 3600 }))),
            ("GET", "/api/accounts/revision-date") => (200, Some(json!(self.rev))),
            ("GET", "/api/sync") => (200, Some(self.sync.clone())),
            ("POST", "/api/folders") => {
                self.rev += 1;
                let folder = json!({ "id": format!("folder{}", self.rev), "name": body["name"] });
                self.sync["folders"].as_array_mut().expect("folders").push(folder.clone());
                (200, Some(folder))
            }
            ("POST", "/api/ciphers") => {
                let id = format!("new{}", self.rev + 1);
                (200, Some(self.store(&id, body)))
            }
            (_, p) if p.starts_with("/api/ciphers/") => {
                let rest = &p["/api/ciphers/".len()..];
                if let Some(id) = rest.strip_suffix("/delete") {
                    self.rev += 1;
                    let rev = self.revision();
                    return match self.find(id) {
                        Some(c) => {
                            c["deletedDate"] = json!(rev);
                            (200, None)
                        }
                        None => (404, None),
                    };
                }
                match method {
                    "GET" => self.find(rest).map_or((404, None), |c| (200, Some(c.clone()))),
                    "PUT" => {
                        if self.fail_puts {
                            return (503, None);
                        }
                        if self.stale_puts > 0 {
                            self.stale_puts -= 1;
                            self.rev += 1;
                            let rev = self.revision();
                            if let Some(c) = self.find(rest) {
                                c["revisionDate"] = json!(rev);
                            }
                        }
                        if let Some(hook) = self.before_put.take() {
                            self.rev += 1;
                            let rev = self.revision();
                            if let Some(c) = self.find(rest) {
                                hook(c);
                                c["revisionDate"] = json!(rev);
                            }
                        }
                        let Some(current) = self.find(rest).map(|c| c["revisionDate"].clone()) else {
                            return (404, None);
                        };
                        if body["lastKnownRevisionDate"] != current {
                            let message =
                                "The client copy of this cipher is out of date. Resync the client and try again.";
                            return (400, Some(json!({ "message": message })));
                        }
                        (200, Some(self.store(rest, body)))
                    }
                    _ => (404, None),
                }
            }
            _ => (404, None),
        }
    }
}

#[derive(Clone)]
struct Fake(Arc<Mutex<Server>>);

impl Fake {
    fn start(sync: Value) -> (Fake, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let fake = Fake(Arc::new(Mutex::new(Server {
            sync,
            rev: 1,
            down: false,
            fail_puts: false,
            stale_puts: 0,
            requests: Vec::new(),
            faults: Vec::new(),
            before_put: None,
            pause: None,
        })));
        let f = fake.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let f = f.clone();
                std::thread::spawn(move || f.serve(stream));
            }
        });
        (fake, url)
    }

    fn serve(&self, stream: TcpStream) {
        let Ok(read_half) = stream.try_clone() else { return };
        let mut reader = BufReader::new(read_half);
        let mut out = stream;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_owned();
            let path = parts.next().unwrap_or_default().to_owned();
            let mut len = 0;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 {
                    return;
                }
                let header = header.trim_end();
                if header.is_empty() {
                    break;
                }
                if let Some((k, v)) = header.split_once(':')
                    && k.eq_ignore_ascii_case("content-length")
                {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; len];
            if reader.read_exact(&mut body).is_err() {
                return;
            }
            let pause = {
                let mut s = self.0.lock().unwrap();
                if s.pause.as_ref().is_some_and(|(m, p, _, _)| *m == method && *p == path) {
                    s.pause.take()
                } else {
                    None
                }
            };
            if let Some((_, _, reached, release)) = pause {
                reached.send(()).ok();
                release.recv().ok();
            }
            let (status, reply) = self.0.lock().unwrap().handle(&method, &path, &body);
            let text = reply.map(|v| v.to_string()).unwrap_or_default();
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                text.len()
            );
            if out.write_all(head.as_bytes()).and_then(|()| out.write_all(text.as_bytes())).is_err() {
                return;
            }
        }
    }

    /// The next `times` requests `method` to a path starting with `prefix`
    /// are answered with `status` and no body.
    fn fault(&self, method: &'static str, prefix: &str, status: u16, times: usize) {
        self.with(|s| s.faults.push(Fault { method, prefix: prefix.into(), status, reply: None, times }));
    }

    /// Like `fault`, with a JSON body.
    fn fault_reply(&self, method: &'static str, prefix: &str, status: u16, reply: Value) {
        self.with(|s| s.faults.push(Fault { method, prefix: prefix.into(), status, reply: Some(reply), times: 1 }));
    }

    fn with<T>(&self, f: impl FnOnce(&mut Server) -> T) -> T {
        f(&mut self.0.lock().unwrap())
    }

    fn cipher(&self, id: &str) -> Value {
        self.with(|s| s.find(id).cloned()).unwrap_or_else(|| panic!("no cipher {id}"))
    }

    /// Requests whose method is `method` and whose path starts with `prefix`.
    fn count(&self, method: &str, prefix: &str) -> usize {
        self.with(|s| s.requests.iter().filter(|(m, p)| m == method && p.starts_with(prefix)).count())
    }
}

struct Vault {
    keys: Keys,
    fake: Fake,
    backend: Arc<Bitwarden>,
    _dir: tempfile::TempDir,
    dir: std::path::PathBuf,
}

fn enc_fields(k: &SymmetricKey, fields: &[(&str, &str)]) -> Value {
    Value::Array(
        fields
            .iter()
            .map(|(n, v)| json!({ "type": 0, "name": k.encrypt_str(n, &OsRandom).unwrap(), "value": k.encrypt_str(v, &OsRandom).unwrap(), "linkedId": null }))
            .collect(),
    )
}

/// A login the user marked by hand, with a field of another tool.
fn hand_marked(k: &SymmetricKey, cid: &str, id: &str) -> Value {
    json!({
        "id": cid, "type": 1, "organizationId": null, "folderId": null, "revisionDate": REV, "creationDate": REV,
        "deletedDate": null, "name": k.encrypt_str("GitHub", &OsRandom).unwrap(), "notes": null, "favorite": false, "reprompt": 0,
        "login": {
            "username": k.encrypt_str("me", &OsRandom).unwrap(), "password": k.encrypt_str("pw", &OsRandom).unwrap(), "totp": null,
            "uris": [{ "uri": k.encrypt_str("https://github.com", &OsRandom).unwrap(), "match": null }],
        },
        "passwordHistory": null,
        "fields": enc_fields(k, &[("bwss:id", id), ("bwss:attr:service", "git"), ("obsidian:id", "o1")]),
    })
}

fn registry_note(k: &SymmetricKey, cid: &str, notes: &str) -> Value {
    json!({
        "id": cid, "type": 2, "organizationId": null, "folderId": null, "revisionDate": REV, "creationDate": REV,
        "deletedDate": null, "name": k.encrypt_str("bwss collections", &OsRandom).unwrap(), "notes": k.encrypt_str(notes, &OsRandom).unwrap(),
        "secureNote": { "type": 0 }, "passwordHistory": null,
        "fields": enc_fields(k, &[("bwss:id", "_collections"), ("bwss:kind", "collections")]),
    })
}

/// A fake server holding `ciphers` for `user`, and what a backend needs to reach it.
fn server(ciphers: Vec<Value>, user: &SymmetricKey) -> (Fake, Config, Credentials, Paths, tempfile::TempDir) {
    serve(json!({ "profile": { "id": "user1", "key": protect(user) }, "folders": [], "ciphers": ciphers }))
}

/// `user` wrapped under the master key of `PASSWORD`, as `profile.key`.
fn protect(user: &SymmetricKey) -> String {
    let kdf = KdfParams::Pbkdf2 { iterations: ITERATIONS };
    // PBKDF2 runs inline: the future is ready at once.
    let master = derive_master_key(PASSWORD, EMAIL, kdf, &NativeArgon2).now_or_never().unwrap().unwrap();
    SymmetricKey::stretch(&master).encrypt(&user.to_bytes(), &OsRandom).unwrap()
}

/// A fake server answering `/sync` with `sync`.
fn serve(sync: Value) -> (Fake, Config, Credentials, Paths, tempfile::TempDir) {
    let (fake, url) = Fake::start(sync);
    let dir = tempfile::tempdir().unwrap();
    let identity_origin = dybw_core::api::origin_of(&url).unwrap();
    let config = Config { server_url: url, email: EMAIL.into(), profile: Some("p".into()), ..Config::default() };
    let paths = paths_in(dir.path());
    let creds = Credentials { identity_origin, client_id: "id".into(), client_secret: Zeroizing::new("secret".into()) };
    (fake, config, creds, paths, dir)
}

async fn vault(ciphers: Vec<Value>, user: SymmetricKey) -> Vault {
    vault_with(ciphers, user, false).await
}

/// `vault` on a device where `bwss derive on` was (or was not) run.
async fn vault_with(ciphers: Vec<Value>, user: SymmetricKey, derive: bool) -> Vault {
    let (fake, config, creds, paths, dir) = server(ciphers, &user);
    if derive {
        crate::config::set_derive(&paths, true).unwrap();
    }
    let backend = Arc::new(Bitwarden::new(&config, creds, &paths).unwrap());
    backend.unlock(PASSWORD).await.unwrap();
    let keys = Keys { marker: Marker::new(&user, MarkScheme::Bwss), user, orgs: BTreeMap::new(), security_version: 0 };
    Vault { keys, fake, backend, dir: dir.path().to_owned(), _dir: dir }
}

fn paths_in(dir: &std::path::Path) -> Paths {
    Paths {
        config: dir.join("config.toml"),
        legacy_config: dir.join("legacy.toml"),
        legacy_credentials: dir.join("legacy-credentials.toml"),
        cache: dir.join("cache"),
        state: dir.join("state"),
        profiles: dir.join("profiles"),
        tool_state: dir.join("tool-state"),
    }
}

#[test]
fn starting_without_a_queue_ends_the_migration_window() {
    let config = Config {
        server_url: "http://127.0.0.1:1".into(),
        email: EMAIL.into(),
        profile: Some("p".into()),
        ..Config::default()
    };
    let creds = || Credentials {
        identity_origin: "http://127.0.0.1:1".into(),
        client_id: "id".into(),
        client_secret: Zeroizing::new("secret".into()),
    };
    let fresh = tempfile::tempdir().unwrap();
    let paths = paths_in(fresh.path());
    BitwardenBackend::new(&config, creds(), &paths).unwrap();
    assert!(crate::config::flag_set(&paths.queue_key_migrated()), "set before any unlock");

    // A queue left by an older bwss keeps the window open for its unlock.
    let upgraded = tempfile::tempdir().unwrap();
    let paths = paths_in(upgraded.path());
    std::fs::create_dir_all(&paths.state).unwrap();
    std::fs::write(paths.state.join("queue.json"), r#"{"format":2,"ops":"x"}"#).unwrap();
    BitwardenBackend::new(&config, creds(), &paths).unwrap();
    assert!(!crate::config::flag_set(&paths.queue_key_migrated()));
}

impl Vault {
    async fn snapshot(&self) -> Snapshot {
        self.backend.refresh().await.unwrap();
        let guard = self.backend.state.lock().await;
        guard.as_ref().unwrap().built.snapshot.clone()
    }

    async fn item(&self, id: &str) -> ItemData {
        self.snapshot().await.items.into_iter().find(|i| i.id == id).unwrap_or_else(|| panic!("no item {id}"))
    }

    fn names(&self, cid: &str) -> Vec<String> {
        field_names(&self.fake.cipher(cid), &self.keys.user).unwrap().into_iter().flatten().collect()
    }

    fn dec(&self, v: &Value) -> String {
        self.keys.user.decrypt_str(v.as_str().unwrap()).unwrap().to_string()
    }

    fn marked(&self, cid: &str) -> super::bitwarden::MarkedItem {
        match scan(&self.fake.cipher(cid), &Namespace::BWSS, &self.keys, &Organizations::None) {
            Scan::Marked(m) => super::bitwarden::to_marked(*m, &self.keys, false),
            other => panic!("expected {cid} marked, got {other:?}"),
        }
    }

    async fn queued(&self) -> usize {
        self.backend.queue.lock().await.len()
    }

    /// The ops in queue.json, opened with the queue key.
    fn queue_file(&self) -> usize {
        match read_formats(&self.dir.join("state/queue.json"), "legacy", &[QUEUE_FORMAT]) {
            Loaded::Ok(v) => {
                let key = super::bitwarden::queue_key(&self.keys.user);
                unseal(&v, &key, v["user_key_id"].as_str().unwrap()).unwrap().0.len()
            }
            Loaded::Missing => 0,
            _ => panic!("queue.json cannot be read"),
        }
    }
}

/// A copy of a key: the core's keys are not `Clone`.
fn core_key(k: &SymmetricKey) -> SymmetricKey {
    dybw_core::crypto::SymmetricKey::from_bytes(&k.to_bytes()).unwrap()
}

impl Vault {
    /// Records that this device already confirmed its first write back to
    /// the login password of `id`, in cipher `cid` (ADR 0016).
    async fn confirm_write_back(&self, id: &str, cid: &str) {
        let queue = self.backend.queue.lock().await;
        let mut guard = self.backend.state.lock().await;
        let state = guard.as_mut().unwrap();
        let record = WriteRecord { written: vec![], confirmed: true, cipher_id: Some(cid.into()) };
        state.records.insert(id.into(), record);
        self.backend.keep_queue(&queue, state).unwrap();
    }
}

fn new_item(id: &str, collection: &str) -> ItemData {
    ItemData {
        id: id.into(),
        collection: collection.into(),
        label: "App token".into(),
        attributes: Attributes::from([("service".to_owned(), "app".to_owned())]),
        secret: Zeroizing::new(b"tok".to_vec()),
        content_type: "text/plain".into(),
        created: 1,
        modified: 1,
        acl: vec!["/usr/bin/app".into()],
    }
}

#[tokio::test]
async fn writes_change_only_bwss_fields_and_the_value_source() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
    v.confirm_write_back("gh", "c1").await;
    let mut item = v.item("gh").await;
    item.secret = Zeroizing::new(b"rotated".to_vec());
    item.label = "GitHub token".into();
    v.backend.put_item(&item).await.unwrap();

    let c = v.fake.cipher("c1");
    assert_eq!(v.dec(&c["login"]["password"]), "rotated");
    assert_eq!(v.dec(&c["passwordHistory"][0]["password"]), "pw");
    assert_eq!(v.dec(&c["name"]), "GitHub", "the item name is the user's");
    assert_eq!(v.dec(&c["login"]["username"]), "me");
    assert_eq!(v.names("c1"), ["bwss:id", "bwss:attr:service", "obsidian:id", "bwss:label"]);
    assert_eq!(v.marked("c1").item.label, "GitHub token");
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 0);

    // Nothing changed: nothing is sent.
    let puts = v.fake.count("PUT", "/api/ciphers/");
    let item = v.item("gh").await;
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.fake.count("PUT", "/api/ciphers/"), puts);
}

#[tokio::test]
async fn deleting_strips_and_trashes_only_bare_items() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    assert_eq!(v.fake.count("POST", "/api/folders"), 1);
    let created = v.fake.with(|s| s.sync["ciphers"][1].clone());
    let cid = created["id"].as_str().unwrap().to_owned();
    assert_eq!(created["type"], 2);
    assert_eq!(v.dec(&v.fake.with(|s| s.sync["folders"][0]["name"].clone())), "secret-service");
    assert_eq!(created["folderId"], v.fake.with(|s| s.sync["folders"][0]["id"].clone()));
    assert_eq!(v.marked(&cid).item.id, "n1");

    let item = v.item("n1").await;
    v.backend.delete_item(&item).await.unwrap();
    assert!(v.fake.cipher(&cid)["deletedDate"].is_string(), "a bare item goes to the trash");

    let item = v.item("gh").await;
    v.backend.delete_item(&item).await.unwrap();
    let c = v.fake.cipher("c1");
    assert!(c["deletedDate"].is_null(), "the user's login stays");
    assert_eq!(v.names("c1"), ["obsidian:id"]);
    assert_eq!(v.dec(&c["login"]["password"]), "pw");
    assert_eq!(v.fake.count("PUT", "/api/ciphers/c1/delete"), 0);
    assert!(v.snapshot().await.items.is_empty());
}

#[tokio::test]
async fn out_of_date_writes_reapply_and_value_conflicts_fail() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], core_key(&k)).await;
    v.confirm_write_back("gh", "c1").await;

    // Another device renamed the item: bwss's label lands on the fresh copy.
    let renamed = k.encrypt_str("Renamed elsewhere", &OsRandom).unwrap();
    v.fake.with(|s| s.before_put = Some(Box::new(move |c: &mut Value| c["name"] = json!(renamed))));
    let mut item = v.item("gh").await;
    item.label = "Mine".into();
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.dec(&v.fake.cipher("c1")["name"]), "Renamed elsewhere");
    assert_eq!(v.marked("c1").item.label, "Mine");

    // Another device changed the password: bwss does not overwrite it.
    let other = k.encrypt_str("theirs", &OsRandom).unwrap();
    v.fake.with(|s| s.before_put = Some(Box::new(move |c: &mut Value| c["login"]["password"] = json!(other))));
    let mut item = v.item("gh").await;
    item.secret = Zeroizing::new(b"ours".to_vec());
    let err = v.backend.put_item(&item).await.unwrap_err();
    assert!(matches!(err, BackendError::Conflict(_)), "{err}");
    assert_eq!(v.dec(&v.fake.cipher("c1")["login"]["password"]), "theirs");
    assert_eq!(v.queued().await, 0);
}

#[tokio::test]
async fn offline_writes_queue_merge_and_replay() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
    v.confirm_write_back("gh", "c1").await;
    v.fake.with(|s| s.down = true);
    let mut item = v.item_offline("gh").await;
    item.secret = Zeroizing::new(b"one".to_vec());
    v.backend.put_item(&item).await.unwrap();
    item.secret = Zeroizing::new(b"two".to_vec());
    item.label = "Two".into();
    v.backend.put_item(&item).await.unwrap();
    // Two changes of one item are one queued patch.
    assert_eq!((v.queued().await, v.queue_file()), (1, 1));
    let raw = std::fs::read_to_string(v.dir.join("state/queue.json")).unwrap();
    // Quoted: a two-letter id may occur in base64 by chance.
    assert!(!raw.contains("two") && !raw.contains("\"gh\""));
    // Too large: refused now, never queued.
    item.label = "x".repeat(4_000);
    assert!(matches!(v.backend.put_item(&item).await, Err(BackendError::Rejected(_))));
    assert_eq!(v.queued().await, 1);

    v.fake.with(|s| s.down = false);
    let puts = v.fake.count("PUT", "/api/ciphers/");
    let snap = v.snapshot().await;
    assert_eq!(v.queued().await, 0);
    assert_eq!(v.queue_file(), 0);
    assert_eq!(v.fake.count("PUT", "/api/ciphers/") - puts, 1);
    assert_eq!(v.dec(&v.fake.cipher("c1")["login"]["password"]), "two");
    assert_eq!(v.dec(&v.fake.cipher("c1")["passwordHistory"][0]["password"]), "pw");
    assert_eq!(snap.items[0].label, "Two");

    // After a lock nothing is queued, and nothing stays in memory.
    v.fake.with(|s| s.down = true);
    v.backend.put_item(&ItemData { label: "Three".into(), ..item.clone() }).await.ok();
    v.backend.lock().await;
    assert_eq!(v.queued().await, 0);
    assert!(matches!(v.backend.put_item(&item).await, Err(BackendError::Locked)));
    assert_eq!(v.queued().await, 0);
}

#[tokio::test]
async fn a_queued_write_survives_a_save_that_re_encrypts_the_same_value() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], core_key(&k)).await;
    v.confirm_write_back("gh", "c1").await;
    v.fake.with(|s| s.down = true);
    let mut item = v.item_offline("gh").await;
    item.secret = Zeroizing::new(b"queued".to_vec());
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.queued().await, 1);

    // Another client renames the item; saving re-encrypts every value with
    // a fresh IV, the unchanged password included.
    let (name, pw) = (k.encrypt_str("Renamed", &OsRandom).unwrap(), k.encrypt_str("pw", &OsRandom).unwrap());
    v.fake.with(|s| {
        s.down = false;
        s.rev += 1;
        let rev = s.revision();
        let c = s.find("c1").unwrap();
        assert_ne!(c["login"]["password"], json!(pw));
        c["name"] = json!(name);
        c["login"]["password"] = json!(pw);
        c["revisionDate"] = json!(rev);
    });
    v.backend.refresh().await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queued().await, 0);
    let c = v.fake.cipher("c1");
    assert_eq!(v.dec(&c["login"]["password"]), "queued");
    assert_eq!(v.dec(&c["name"]), "Renamed");
}

#[tokio::test]
async fn a_queued_value_conflict_keeps_the_rest_of_the_change() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], core_key(&k)).await;
    v.confirm_write_back("gh", "c1").await;
    v.fake.with(|s| s.down = true);
    let mut item = v.item_offline("gh").await;
    item.secret = Zeroizing::new(b"ours".to_vec());
    item.label = "Queued".into();
    item.attributes.insert("user".into(), "me".into());
    item.acl.push("/usr/bin/app".into());
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.queued().await, 1);

    // Another device changes the password meanwhile.
    let theirs = k.encrypt_str("theirs", &OsRandom).unwrap();
    v.fake.with(|s| {
        s.down = false;
        s.rev += 1;
        let rev = s.revision();
        let c = s.find("c1").unwrap();
        c["login"]["password"] = json!(theirs);
        c["revisionDate"] = json!(rev);
    });
    v.backend.refresh().await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!((v.queued().await, v.queue_file()), (0, 0));
    let m = v.marked("c1");
    assert_eq!(&*m.item.secret, b"theirs", "the other device's password stays");
    assert_eq!(m.item.label, "Queued");
    assert_eq!(m.item.attributes.get("user").map(String::as_str), Some("me"));
    assert_eq!(m.item.acl, ["/usr/bin/app"]);
}

#[tokio::test]
async fn a_change_that_cannot_be_kept_on_disk_is_refused() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
    v.fake.with(|s| s.down = true);
    // The private write goes through this temporary name: a directory there
    // makes it fail, for any user.
    let queue = v.dir.join("state/queue.json");
    std::fs::create_dir_all(crate::fsutil::temp_path(&queue)).unwrap();
    let item = ItemData { label: "Queued".into(), ..v.item_offline("gh").await };
    let result = v.backend.put_item(&item).await;
    assert!(
        matches!(&result, Err(BackendError::Unavailable(m)) if m.contains("cannot be queued on disk")),
        "{result:?}"
    );
    assert_eq!(v.queued().await, 0, "a change not on disk is not kept in memory either");
    assert_eq!(v.item_offline("gh").await.label, "gh");
    assert!(!queue.exists());
}

impl Vault {
    /// The item as the backend shows it, without a refresh.
    async fn item_offline(&self, id: &str) -> ItemData {
        let guard = self.backend.state.lock().await;
        guard.as_ref().unwrap().built.marked[id].item.clone()
    }
}

#[tokio::test]
async fn queued_changes_wait_for_unreadable_items_and_drop_for_gone_ones() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let other = json!({
        "id": "c2", "type": 2, "organizationId": null, "folderId": null, "revisionDate": REV, "creationDate": REV,
        "deletedDate": null, "name": k.encrypt_str("Other", &OsRandom).unwrap(), "notes": null, "secureNote": { "type": 0 },
        "passwordHistory": null, "fields": enc_fields(&k, &[("bwss:id", "x"), ("bwss:password", "s")]),
    });
    let v = vault(vec![hand_marked(&k, "c1", "gh"), other], k).await;
    v.confirm_write_back("gh", "c1").await;
    v.fake.with(|s| s.down = true);
    let mut item = v.item_offline("gh").await;
    item.secret = Zeroizing::new(b"queued".to_vec());
    v.backend.put_item(&item).await.unwrap();
    let x = v.item_offline("x").await;
    v.backend.delete_item(&x).await.unwrap();
    assert_eq!(v.queued().await, 2);

    // Meanwhile c1 became unreadable (a key bwss cannot unwrap) and c2 was
    // trashed elsewhere.
    let good_key = v.fake.cipher("c1")["key"].clone();
    v.fake.with(|s| {
        s.down = false;
        s.rev += 1;
        let rev = s.revision();
        let c1 = s.find("c1").unwrap();
        c1["key"] = json!("2.AAAA|AAAA|AAAA");
        c1["revisionDate"] = json!(rev);
        s.find("c2").unwrap()["deletedDate"] = json!(rev);
    });
    v.backend.refresh().await.unwrap();
    v.backend.refresh().await.unwrap();
    // Only that item's ops wait (the core's queue): the delete of the item
    // that is gone is done.
    assert_eq!(v.queued().await, 1, "a change to an item that cannot be read waits");
    assert_eq!(v.queue_file(), 1);
    // Also after a new unlock, when nothing is held yet.
    v.backend.lock().await;
    v.backend.unlock(PASSWORD).await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!((v.queued().await, v.queue_file()), (1, 1));

    // Readable again: the change goes through.
    v.fake.with(|s| {
        s.rev += 1;
        let rev = s.revision();
        let c1 = s.find("c1").unwrap();
        c1["key"] = good_key;
        c1["revisionDate"] = json!(rev);
    });
    v.backend.refresh().await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queued().await, 0);
    assert_eq!(v.dec(&v.fake.cipher("c1")["login"]["password"]), "queued");
}

#[tokio::test]
async fn an_unrelated_unreadable_item_never_holds_the_queue() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh"), hand_marked(&k, "c2", "x")], k).await;
    v.fake.with(|s| s.down = true);
    let item = ItemData { label: "Queued".into(), ..v.item_offline("gh").await };
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.queued().await, 1);

    // c1 is trashed elsewhere and c2, another item, becomes unreadable.
    v.fake.with(|s| {
        s.down = false;
        s.rev += 1;
        let rev = s.revision();
        s.find("c1").unwrap()["deletedDate"] = json!(rev);
        let c2 = s.find("c2").unwrap();
        c2["key"] = json!("2.AAAA|AAAA|AAAA");
        c2["revisionDate"] = json!(rev);
    });
    // Also after a new unlock, when nothing is held yet.
    v.backend.lock().await;
    v.backend.unlock(PASSWORD).await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!((v.queued().await, v.queue_file()), (0, 0), "the change to the trashed item is dropped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accepted_create_leaves_the_queue_even_when_the_keyring_locks() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![], k).await;
    v.fake.with(|s| s.down = true);
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    assert_eq!(v.queue_file(), 1);

    let (reached_tx, reached) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    v.fake.with(|s| {
        s.down = false;
        s.pause = Some(("POST".into(), "/api/ciphers".into(), reached_tx, release_rx));
    });
    let backend = v.backend.clone();
    let local = tokio::task::LocalSet::new();
    // The core's futures are not `Send`: the flush runs on this thread.
    let flush = local.spawn_local(async move { backend.refresh().await });
    local.run_until(tokio::task::spawn_blocking(move || reached.recv().unwrap())).await.unwrap();
    // `lock` drops the keys at once, then waits for the request in flight
    // to log out.
    let backend = v.backend.clone();
    let locking = tokio::spawn(async move { backend.lock().await });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while v.backend.state.lock().await.is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("lock drops the keys");
    release.send(()).unwrap();
    let _ = local.run_until(flush).await.unwrap();
    locking.await.unwrap();

    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1);
    assert_eq!(v.queue_file(), 0, "the accepted create is not replayed");
    assert_eq!(v.queued().await, 0);
    // A new unlock does not create it again.
    v.backend.unlock(PASSWORD).await.unwrap();
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1);
}

#[tokio::test]
async fn collections_live_in_the_registry_note() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![], k).await;
    let work = v.backend.create_collection("Work").await.unwrap();
    assert_eq!(work.id, "work");
    let note = v.fake.with(|s| s.sync["ciphers"][0].clone());
    let cid = note["id"].as_str().unwrap().to_owned();
    let registry = Registry::try_parse(&v.dec(&note["notes"])).unwrap();
    assert_eq!(registry.0["work"].label, "Work");
    assert!(v.snapshot().await.collections.iter().any(|c| c.id == "work"));

    // A second one merges into the same note.
    let home = v.backend.create_collection("Work").await.unwrap();
    assert_eq!(home.id, "work-2");
    let registry = Registry::try_parse(&v.dec(&v.fake.cipher(&cid)["notes"])).unwrap();
    assert_eq!(registry.0.len(), 2);

    v.backend.put_item(&new_item("n1", "work")).await.unwrap();
    v.snapshot().await;
    // An item that joined after the caller authorized the others is never
    // deleted: the whole delete is refused.
    assert!(matches!(v.backend.delete_collection("work", &[]).await, Err(BackendError::Rejected(_))));
    let n1 = v.fake.with(|s| s.sync["ciphers"].as_array().unwrap().last().unwrap().clone());
    let n1 = n1["id"].as_str().unwrap().to_owned();
    assert!(v.fake.cipher(&n1)["deletedDate"].is_null());
    assert_eq!(v.marked(&n1).item.id, "n1");
    v.backend.delete_collection("work", &["n1".to_owned()]).await.unwrap();
    let registry = Registry::try_parse(&v.dec(&v.fake.cipher(&cid)["notes"])).unwrap();
    assert!(registry.0["work"].deleted);
    let snap = v.snapshot().await;
    assert!(snap.items.is_empty());
    assert!(!snap.collections.iter().any(|c| c.id == "work"));
    assert!(snap.collections.iter().any(|c| c.id == "work-2"));
}

#[tokio::test]
async fn a_queued_tombstone_never_buries_a_newer_collection() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![registry_note(&k, "r1", r#"{"work":{"label":"Work","created":5}}"#)], core_key(&k)).await;
    v.fake.with(|s| s.down = true);
    v.backend.delete_collection("work", &[]).await.unwrap();
    assert_eq!(v.queued().await, 1);

    // Another device deleted and created it again meanwhile.
    let notes = k.encrypt_str(r#"{"work":{"label":"Work again","created":100}}"#, &OsRandom).unwrap();
    v.fake.with(|s| {
        s.down = false;
        s.rev += 1;
        let rev = s.revision();
        let c = s.find("r1").unwrap();
        c["notes"] = json!(notes);
        c["revisionDate"] = json!(rev);
    });
    v.backend.refresh().await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queued().await, 0);
    let registry = Registry::try_parse(&v.dec(&v.fake.cipher("r1")["notes"])).unwrap();
    assert!(!registry.0["work"].deleted, "{registry:?}");
    assert_eq!(registry.0["work"].created, 100);
    assert!(v.snapshot().await.collections.iter().any(|c| c.id == "work"));
}

#[tokio::test]
async fn an_unreadable_registry_is_never_written() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![registry_note(&k, "r1", "not json")], k).await;
    let writes = || v.fake.count("PUT", "/api/") + v.fake.count("POST", "/api/");
    let before = writes();
    assert!(matches!(v.backend.create_collection("Work").await, Err(BackendError::Rejected(_))));
    assert!(matches!(v.backend.delete_collection("home", &[]).await, Err(BackendError::Rejected(_))));
    assert_eq!(writes(), before);
    assert!(v.backend.describe().await.contains("collection registry cannot be read"));
}

#[tokio::test]
async fn status_lists_duplicates() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let mut clone = hand_marked(&k, "c2", "gh");
    clone["creationDate"] = json!("2026-06-01T00:00:00Z");
    let twin = hand_marked(&k, "c3", "twin");
    let v = vault(vec![hand_marked(&k, "c1", "gh"), clone, twin], k).await;
    let status = v.backend.describe().await;
    assert!(status.contains("duplicate id gh: 1 items ignored"), "{status}");
    assert!(status.contains("possible duplicates: gh (gh), twin (twin)"), "{status}");
}

#[tokio::test]
async fn a_write_read_from_the_server_replaces_a_queued_one() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh"), hand_marked(&k, "c2", "x")], core_key(&k)).await;
    v.confirm_write_back("gh", "c1").await;
    // A delete that cannot be sent keeps the queue blocked, so the change
    // below stays queued across refreshes.
    v.fake.with(|s| s.fail_puts = true);
    let x = v.item_offline("x").await;
    v.backend.delete_item(&x).await.unwrap();
    let mut item = v.item_offline("gh").await;
    item.secret = Zeroizing::new(b"one".to_vec());
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.queued().await, 2);

    // Another device changes the password; the refresh shows it, since the
    // queued change cannot be applied to it.
    let theirs = k.encrypt_str("theirs", &OsRandom).unwrap();
    v.fake.with(|s| {
        s.rev += 1;
        let rev = s.revision();
        let c = s.find("c1").unwrap();
        c["login"]["password"] = json!(theirs);
        c["revisionDate"] = json!(rev);
    });
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queued().await, 2);
    let mut item = v.item_offline("gh").await;
    assert_eq!(&*item.secret, b"theirs");

    // The app writes again, from what the server holds: that write lands.
    item.secret = Zeroizing::new(b"two".to_vec());
    v.backend.put_item(&item).await.unwrap();
    v.fake.with(|s| s.fail_puts = false);
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queued().await, 0);
    assert_eq!(v.dec(&v.fake.cipher("c1")["login"]["password"]), "two");
}

#[tokio::test]
async fn text_after_a_queued_binary_write_never_reaches_the_login_password() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
    v.fake.with(|s| s.down = true);
    let mut item = v.item_offline("gh").await;
    item.secret = Zeroizing::new(vec![0xff, 0]);
    v.backend.put_item(&item).await.unwrap();
    let mut item = v.item_offline("gh").await;
    item.secret = Zeroizing::new(b"text".to_vec());
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.queued().await, 1);

    v.fake.with(|s| s.down = false);
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queued().await, 0);
    let c = v.fake.cipher("c1");
    assert_eq!(v.dec(&c["login"]["password"]), "pw", "the user's password is untouched");
    assert!(c["passwordHistory"].as_array().is_none_or(Vec::is_empty));
    assert!(!v.names("c1").iter().any(|n| n == "bwss:encoding"));
    let m = v.marked("c1");
    assert_eq!((m.source, m.item.secret.as_slice()), (dybw_core::vault::ValueSource::Field, &b"text"[..]));
}

#[tokio::test]
async fn a_write_out_of_date_on_every_attempt_is_retried_never_lost() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;

    // Live: the app is told to try again, and nothing is queued.
    v.fake.with(|s| s.stale_puts = 3);
    let mut item = v.item("gh").await;
    item.label = "Mine".into();
    let err = v.backend.put_item(&item).await.unwrap_err();
    assert!(matches!(&err, BackendError::Unavailable(m) if m.ends_with("try again")), "{err}");
    assert_eq!(v.queued().await, 0);
    assert!(!v.names("c1").iter().any(|n| n == "bwss:label"));

    // Queued: it stays queued, and goes through later.
    v.fake.with(|s| s.down = true);
    let item = ItemData { label: "Queued".into(), ..v.item_offline("gh").await };
    v.backend.put_item(&item).await.unwrap();
    v.fake.with(|s| {
        s.down = false;
        s.stale_puts = 6;
    });
    v.backend.refresh().await.unwrap();
    assert_eq!((v.queued().await, v.queue_file()), (1, 1));
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queued().await, 0);
    assert_eq!(v.marked("c1").item.label, "Queued");
}

#[tokio::test]
async fn a_delete_keeps_an_item_that_gained_foreign_content_meanwhile() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![], core_key(&k)).await;
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    let cid = v.fake.with(|s| s.sync["ciphers"][0]["id"].as_str().unwrap().to_owned());
    let item = v.item("n1").await;

    // While bwss saves the stripped item, another device adds a note field:
    // the save is out of date, and the retry keeps that field.
    let (name, value) = (k.encrypt_str("note", &OsRandom).unwrap(), k.encrypt_str("mine", &OsRandom).unwrap());
    v.fake.with(|s| {
        s.before_put = Some(Box::new(move |c: &mut Value| {
            c["fields"].as_array_mut().unwrap().push(json!({ "type": 0, "name": name, "value": value }));
        }))
    });
    v.backend.delete_item(&item).await.unwrap();
    assert!(v.fake.cipher(&cid)["deletedDate"].is_null(), "an item with foreign content is never trashed");
    assert_eq!(v.names(&cid), ["note"]);
    assert_eq!(v.fake.count("PUT", &format!("/api/ciphers/{cid}/delete")), 0);
}

#[tokio::test]
async fn acl_decisions_are_keyed_by_a_key_of_their_own() {
    let user = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![], core_key(&user)).await;
    match v.backend.acl_trust().await.unwrap() {
        super::AclTrust::PerDevice(key) => {
            assert_eq!(key.to_bytes(), user.derive_bwss("acl-confirm").to_bytes());
            assert_ne!(key.to_bytes(), user.to_bytes());
        }
        super::AclTrust::Local => panic!("synced lines must be confirmed per device"),
    }
    v.backend.lock().await;
    assert!(matches!(v.backend.acl_trust().await, Err(BackendError::Locked)));
}

// --- ADR 0016: the password history ------------------------------------------

#[tokio::test]
async fn keep_separate_moves_the_value_to_a_field() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let mut login = hand_marked(&k, "c1", "gh");
    // A full history of passwords this device never wrote.
    let history: Vec<Value> = (1..=5)
        .map(|n| json!({ "password": k.encrypt_str(&format!("old{n}"), &OsRandom).unwrap(), "lastUsedDate": REV }))
        .collect();
    login["passwordHistory"] = json!(history);
    let v = vault(vec![login], k).await;
    let puts = v.fake.count("PUT", "/api/ciphers/");
    let item = ItemData { secret: Zeroizing::new(b"app".to_vec()), ..v.item_offline("gh").await };
    // The eviction is asked, over the first write-back.
    let err = v.backend.put_item(&item).await.unwrap_err();
    assert!(matches!(err, BackendError::Ask(HistoryQuestion::EvictsForeign)), "{err}");
    assert_eq!(v.fake.count("PUT", "/api/ciphers/"), puts, "nothing was written");
    assert_eq!(v.queued().await, 0, "nothing was queued");
    // An answer to another question does not cover it.
    let other = (HistoryQuestion::FirstWriteBack, HistoryAnswer::WriteToLogin);
    let err = v.backend.put_item_answered(&item, Some(other)).await.unwrap_err();
    assert!(matches!(err, BackendError::Ask(HistoryQuestion::EvictsForeign)), "{err}");

    let answer = (HistoryQuestion::EvictsForeign, HistoryAnswer::KeepSeparate);
    v.backend.put_item_answered(&item, Some(answer)).await.unwrap();
    let c = v.fake.cipher("c1");
    assert_eq!(v.dec(&c["login"]["password"]), "pw", "the login password stays");
    assert_eq!(c["passwordHistory"].as_array().unwrap().len(), 5);
    assert_eq!(v.dec(&c["passwordHistory"][4]["password"]), "old5", "and its history");
    let field = c["fields"].as_array().unwrap().iter().find(|f| v.dec(&f["name"]) == "bwss:password").unwrap();
    assert_eq!((field["type"].as_u64(), v.dec(&field["value"])), (Some(1), "app".to_owned()), "hidden");
    let m = v.marked("c1");
    assert_eq!((m.source, m.item.secret.as_slice()), (dybw_core::vault::ValueSource::Field, &b"app"[..]));
    // From then on the field is the value source: no more questions.
    v.backend.put_item(&ItemData { secret: Zeroizing::new(b"again".to_vec()), ..item }).await.unwrap();
    assert_eq!(v.dec(&v.fake.cipher("c1")["login"]["password"]), "pw");
}

#[tokio::test]
async fn a_queued_question_waits_for_bwss_answer() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh"), hand_marked(&k, "c2", "x"), hand_marked(&k, "c3", "y")], k).await;
    // Offline since the unlock: a live write would ask through the pinentry instead.
    v.fake.with(|s| s.down = true);
    *v.backend.client.lock().await = None;
    for id in ["gh", "x", "y"] {
        let item = ItemData { secret: Zeroizing::new(b"queued".to_vec()), ..v.item_offline(id).await };
        v.backend.put_item(&item).await.unwrap();
    }
    assert_eq!(v.queue_sizes().await, (3, 3));

    // Sent, the first write-back of each login needs an answer: all wait.
    v.fake.with(|s| s.down = false);
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (3, 3), "the changes wait, never dropped");
    assert_eq!(v.dec(&v.fake.cipher("c1")["login"]["password"]), "pw");
    let status = v.backend.describe().await;
    assert!(status.contains("waits for your answer: the first change from this device"), "{status}");
    assert!(status.contains("`bwss answer gh login|separate|cancel`"), "{status}");
    let first = HistoryQuestion::FirstWriteBack;
    assert_eq!(v.backend.queued_question("gh").await.unwrap(), Some(first));

    // A file is no consent: an answer written where B5 kept them is never read.
    let planted = br#"[{"id":"gh","question":"FirstWriteBack","answer":"login"}]"#;
    v.storage().save("history-answers", planted).await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (3, 3));
    assert_eq!(v.dec(&v.fake.cipher("c1")["login"]["password"]), "pw");

    // An answer to another question than the one asked counts for nothing.
    let stale = v.backend.answer_queued("gh", HistoryQuestion::EvictsForeign, Some(HistoryAnswer::WriteToLogin)).await;
    assert!(matches!(&stale, Err(BackendError::Rejected(m)) if m.contains("no queued change of gh")), "{stale:?}");

    // The answers the daemon confirmed: gh goes to the login, x is cancelled,
    // y keeps its own field. Each is on disk at once.
    v.backend.answer_queued("gh", first, Some(HistoryAnswer::WriteToLogin)).await.unwrap();
    // A cancel that cannot be kept on disk leaves the change queued, in memory too.
    let file = v.dir.join("state/queue.json");
    std::fs::create_dir_all(crate::fsutil::temp_path(&file)).unwrap();
    assert!(matches!(v.backend.answer_queued("x", first, None).await, Err(BackendError::Unavailable(_))));
    assert_eq!(v.queued().await, 3);
    std::fs::remove_dir(crate::fsutil::temp_path(&file)).unwrap();
    v.backend.answer_queued("x", first, None).await.unwrap();
    assert_eq!(v.queue_sizes().await, (2, 2), "x had only its value to change: nothing is left of it");
    v.backend.answer_queued("y", first, Some(HistoryAnswer::KeepSeparate)).await.unwrap();
    assert!(!v.backend.describe().await.contains("waits for your answer"));
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    let c = v.fake.cipher("c1");
    assert_eq!(
        (v.dec(&c["login"]["password"]), v.dec(&c["passwordHistory"][0]["password"])),
        ("queued".into(), "pw".into())
    );
    assert_eq!(v.dec(&v.fake.cipher("c2")["login"]["password"]), "pw", "the cancelled change is gone");
    assert_eq!(v.dec(&v.fake.cipher("c3")["login"]["password"]), "pw", "the login stays");
    assert_eq!(&*v.marked("c3").item.secret, b"queued", "the value is in its own field");
    assert_eq!(v.backend.queued_question("gh").await.unwrap(), None);

    // The write is recorded: the next one to gh asks nothing, even after a restart.
    v.backend.lock().await;
    assert!(matches!(v.backend.queued_question("gh").await, Err(BackendError::Locked)));
    v.backend.unlock(PASSWORD).await.unwrap();
    let item = ItemData { secret: Zeroizing::new(b"later".to_vec()), ..v.item_offline("gh").await };
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.dec(&v.fake.cipher("c1")["login"]["password"]), "later");
}

#[tokio::test]
async fn a_cancelled_queued_answer_keeps_the_other_changes() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
    v.fake.with(|s| s.down = true);
    *v.backend.client.lock().await = None;
    let item =
        ItemData { label: "Renamed".into(), secret: Zeroizing::new(b"queued".to_vec()), ..v.item_offline("gh").await };
    v.backend.put_item(&item).await.unwrap();
    v.fake.with(|s| s.down = false);
    v.backend.refresh().await.unwrap();
    let first = HistoryQuestion::FirstWriteBack;
    assert_eq!(v.backend.queued_question("gh").await.unwrap(), Some(first));

    // An answer that cannot be kept on disk is not kept in memory either.
    let queue = v.dir.join("state/queue.json");
    std::fs::create_dir_all(crate::fsutil::temp_path(&queue)).unwrap();
    let err = v.backend.answer_queued("gh", first, None).await.unwrap_err();
    assert!(matches!(&err, BackendError::Unavailable(m) if m.contains("cannot be kept on disk")), "{err}");
    assert_eq!(v.backend.queued_question("gh").await.unwrap(), Some(first), "still asked");
    std::fs::remove_dir(crate::fsutil::temp_path(&queue)).unwrap();

    v.backend.answer_queued("gh", first, None).await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1), "the label change stays");
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    let m = v.marked("c1");
    assert_eq!((m.item.label.as_str(), m.item.secret.as_slice()), ("Renamed", &b"pw"[..]));
}

#[tokio::test]
async fn a_stuck_item_does_not_queue_writes_to_other_items() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh"), hand_marked(&k, "c2", "x")], k).await;
    v.confirm_write_back("x", "c2").await;
    v.fake.with(|s| s.down = true);
    *v.backend.client.lock().await = None;
    let item = ItemData { secret: Zeroizing::new(b"queued".to_vec()), ..v.item_offline("gh").await };
    v.backend.put_item(&item).await.unwrap();
    v.fake.with(|s| s.down = false);
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1), "gh waits for an answer");

    // Another item's write is sent at once.
    let puts = v.fake.count("PUT", "/api/ciphers/c2");
    let other =
        ItemData { label: "Other".into(), secret: Zeroizing::new(b"new".to_vec()), ..v.item_offline("x").await };
    v.backend.put_item(&other).await.unwrap();
    assert_eq!(v.fake.count("PUT", "/api/ciphers/c2"), puts + 1);
    assert_eq!(v.queue_sizes().await, (1, 1));
    assert_eq!(v.dec(&v.fake.cipher("c2")["login"]["password"]), "new");

    // The same item's next write keeps its order: it queues behind the first.
    let puts = v.fake.count("PUT", "/api/ciphers/c1");
    let later = ItemData { label: "Later".into(), ..v.item_offline("gh").await };
    v.backend.put_item(&later).await.unwrap();
    assert_eq!(v.fake.count("PUT", "/api/ciphers/c1"), puts, "nothing sent for gh");
    assert_eq!(v.queue_sizes().await, (1, 1), "merged into the queued change");
    assert_eq!(v.item_offline("gh").await.label, "Later");
}

#[tokio::test]
async fn acl_lines_union_after_an_out_of_date_retry() {
    let v = github().await;
    // Another device grants its own app while this one grants another.
    let (name, value) = (
        v.keys.user.encrypt_str("bwss:acl", &OsRandom).unwrap(),
        v.keys.user.encrypt_str("/usr/bin/theirs", &OsRandom).unwrap(),
    );
    v.fake.with(|s| {
        s.before_put = Some(Box::new(move |c: &mut Value| {
            c["fields"].as_array_mut().unwrap().push(json!({ "type": 1, "name": name, "value": value }));
        }))
    });
    let mut item = v.item_offline("gh").await;
    item.acl.push("/usr/bin/mine".into());
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.fake.count("PUT", "/api/ciphers/c1"), 2, "out of date once, then sent again");
    assert_eq!(v.marked("c1").item.acl, ["/usr/bin/theirs", "/usr/bin/mine"], "both lines are kept");
    assert_eq!(v.item_offline("gh").await.acl, ["/usr/bin/theirs", "/usr/bin/mine"]);

    // Queued, the union is made with what the server holds when it is sent.
    let v = github().await;
    v.fake.with(|s| s.down = true);
    let mut item = v.item_offline("gh").await;
    item.acl.push("/usr/bin/mine".into());
    v.backend.put_item(&item).await.unwrap();
    v.fake.with(|s| s.down = false);
    v.add_field("c1", "bwss:acl", "/usr/bin/theirs");
    v.edit_elsewhere("c1", |_| {});
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert_eq!(v.marked("c1").item.acl, ["/usr/bin/theirs", "/usr/bin/mine"]);
}

#[tokio::test]
async fn a_write_record_belongs_to_its_cipher() {
    let v = github().await;
    // A record of another cipher (the item was recreated elsewhere) counts for nothing here.
    v.backend.state.lock().await.as_mut().unwrap().records.get_mut("gh").unwrap().cipher_id = Some("c9".into());
    let item = ItemData { secret: Zeroizing::new(b"new".to_vec()), ..v.item_offline("gh").await };
    let err = v.backend.put_item(&item).await.unwrap_err();
    assert!(matches!(err, BackendError::Ask(HistoryQuestion::FirstWriteBack)), "{err}");
    let answer = (HistoryQuestion::FirstWriteBack, HistoryAnswer::WriteToLogin);
    v.backend.put_item_answered(&item, Some(answer)).await.unwrap();
    let records = v.backend.state.lock().await.as_ref().unwrap().records["gh"].clone();
    assert_eq!((records.cipher_id.as_deref(), records.confirmed, records.written.len()), (Some("c1"), true, 1));
}

#[tokio::test]
async fn write_records_that_cannot_be_kept_ask_again() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
    // The records live in the queue file: a directory where its temporary
    // copy goes makes writing it fail, for any user.
    let blocker = crate::fsutil::temp_path(&v.dir.join("state/queue.json"));
    std::fs::create_dir_all(&blocker).unwrap();
    let item = ItemData { secret: Zeroizing::new(b"new".to_vec()), ..v.item_offline("gh").await };
    let err = v.backend.put_item(&item).await.unwrap_err();
    assert!(matches!(err, BackendError::Ask(HistoryQuestion::FirstWriteBack)), "{err}");
    let answer = (HistoryQuestion::FirstWriteBack, HistoryAnswer::WriteToLogin);
    v.backend.put_item_answered(&item, Some(answer)).await.unwrap();
    assert!(v.backend.state.lock().await.as_ref().unwrap().records["gh"].confirmed, "kept in memory");
    // Not on disk: after a restart the next write asks again.
    std::fs::remove_dir(&blocker).unwrap();
    v.backend.lock().await;
    v.backend.unlock(PASSWORD).await.unwrap();
    assert!(v.backend.state.lock().await.as_ref().unwrap().records.is_empty());
    let item = ItemData { secret: Zeroizing::new(b"newer".to_vec()), ..v.item_offline("gh").await };
    let err = v.backend.put_item(&item).await.unwrap_err();
    assert!(matches!(err, BackendError::Ask(HistoryQuestion::FirstWriteBack)), "{err}");
    // Kept this time, in the queue file: a restart does not ask again.
    v.backend.put_item_answered(&item, Some(answer)).await.unwrap();
    v.backend.lock().await;
    v.backend.unlock(PASSWORD).await.unwrap();
    assert!(v.backend.state.lock().await.as_ref().unwrap().records["gh"].confirmed);
    let item = ItemData { secret: Zeroizing::new(b"newest".to_vec()), ..v.item_offline("gh").await };
    v.backend.put_item(&item).await.unwrap();
}

#[tokio::test]
async fn a_queued_change_of_an_item_never_readable_is_listed() {
    let v = github().await;
    v.backend.state.lock().await.as_mut().unwrap().stuck =
        vec![("gh".into(), dybw_core::vault::Uninspectable::TooLarge)];
    let status = v.backend.describe().await;
    assert!(status.contains("a queued change of gh (gh) waits: it is larger than any item bwss reads"), "{status}");

    // A label from the vault reaches the terminal on one line, without escapes.
    if let Some(m) = v.backend.state.lock().await.as_mut().unwrap().built.marked.get_mut("gh") {
        m.item.label = "evil\n\u{1b}[2Jline".into();
    }
    let status = v.backend.describe().await;
    assert!(status.contains("a queued change of evil\u{fffd}\u{fffd}[2Jline (gh) waits"), "{status}");
    assert!(!status.contains('\u{1b}'));
}

#[tokio::test]
async fn a_live_op_without_a_session_waits() {
    let v = github().await;
    *v.backend.client.lock().await = None;
    let item = ItemData { label: "Mine".into(), ..v.item_offline("gh").await };
    let Op::Patch(p) =
        super::runner::plan_put(Some(&v.backend.state.lock().await.as_ref().unwrap().built.marked["gh"]), &item)
    else {
        panic!("a patch")
    };
    let failed = v.backend.run(&Queue::default(), &Op::Patch(p)).await.unwrap_err();
    assert!(format!("{failed:?}").contains("not logged in"), "{failed:?}");
}

#[tokio::test]
async fn a_delete_of_an_item_the_cache_no_longer_holds_sends_nothing() {
    let v = github().await;
    v.backend.state.lock().await.as_mut().unwrap().sync["ciphers"] = json!([]);
    let puts = v.fake.count("PUT", "/api/");
    v.backend.delete_item(&v.item_offline("gh").await).await.unwrap();
    assert_eq!(v.fake.count("PUT", "/api/"), puts);
}

#[tokio::test]
async fn collection_changes_queue_only_behind_collection_changes() {
    let v = github().await;
    v.fake.with(|s| s.down = true);
    let item = ItemData { label: "Queued".into(), ..v.item_offline("gh").await };
    v.backend.put_item(&item).await.unwrap();
    v.backend.create_collection("Home").await.unwrap();
    v.fake.with(|s| s.down = false);
    // The server is back. An item change queued does not hold a collection
    // change, but a queued collection change does: the registry keeps its order.
    v.backend.create_collection("Work").await.unwrap();
    assert_eq!(v.queue_sizes().await, (3, 3));
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 0);
    // A collection change that cannot be kept on disk is refused.
    let queue = v.dir.join("state/queue.json");
    std::fs::create_dir_all(crate::fsutil::temp_path(&queue)).unwrap();
    let err = v.backend.create_collection("Play").await.unwrap_err();
    assert!(matches!(&err, BackendError::Unavailable(m) if m.contains("cannot be queued on disk")), "{err}");
    assert_eq!(v.queued().await, 3);
    std::fs::remove_dir(crate::fsutil::temp_path(&queue)).unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    let ids: Vec<_> = v.snapshot().await.collections.into_iter().map(|c| c.id).collect();
    assert!(ids.contains(&"work".into()) && ids.contains(&"home".into()), "{ids:?}");

    // With nothing queued for the registry, a collection change is sent at
    // once, even beside a queued item change.
    v.fake.with(|s| s.down = true);
    v.backend.put_item(&ItemData { label: "Again".into(), ..v.item_offline("gh").await }).await.unwrap();
    v.fake.with(|s| s.down = false);
    v.backend.create_collection("Live").await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1), "only the item change is queued");
}

#[tokio::test]
async fn a_queued_collection_change_the_server_refuses_is_dropped() {
    let v = with_registry().await;
    v.fake.with(|s| s.down = true);
    v.backend.create_collection("Work").await.unwrap();
    v.fake.with(|s| s.down = false);
    v.fake.fault("PUT", "/api/ciphers/r1", 400, 1);
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert!(!v.snapshot().await.collections.iter().any(|c| c.id == "work"), "the view goes back");
}

#[tokio::test]
async fn a_vault_that_cannot_be_read_after_a_flush_is_read_at_the_next_sync() {
    let v = github().await;
    v.fake.with(|s| s.down = true);
    let item = ItemData { label: "Queued".into(), ..v.item_offline("gh").await };
    v.backend.put_item(&item).await.unwrap();
    v.fake.with(|s| s.down = false);
    // The flush is sent; the read right after it fails once.
    v.fake.fault("GET", "/api/sync", 500, 1);
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert_eq!(v.item_offline("gh").await.label, "Queued");
    assert!(v.logged_in().await, "a failed read keeps the session");
}

// --- what goes wrong on the server ---------------------------------------------

impl Vault {
    async fn has_item(&self, id: &str) -> bool {
        self.backend.state.lock().await.as_ref().unwrap().built.marked.contains_key(id)
    }

    async fn logged_in(&self) -> bool {
        self.backend.client.lock().await.is_some()
    }

    /// Another device adds a field to `cid`. The server's revision stays
    /// as it is, so a refresh does not look at it.
    fn add_field(&self, cid: &str, name: &str, value: &str) {
        let field = json!({
            "type": 0, "name": self.keys.user.encrypt_str(name, &OsRandom).unwrap(), "value": self.keys.user.encrypt_str(value, &OsRandom).unwrap(),
            "linkedId": null,
        });
        self.fake.with(|s| s.find(cid).unwrap()["fields"].as_array_mut().unwrap().push(field));
    }

    /// Another device changes `cid` with `edit`, and the vault's revision moves.
    fn edit_elsewhere(&self, cid: &str, edit: impl FnOnce(&mut Value)) {
        self.fake.with(|s| {
            s.rev += 1;
            let rev = s.revision();
            let c = s.find(cid).unwrap();
            edit(c);
            c["revisionDate"] = json!(rev);
        });
    }

    /// The write queue, shown and on disk.
    async fn queue_sizes(&self) -> (usize, usize) {
        (self.queued().await, self.queue_file())
    }
}

/// A request the fake server holds until it is released.
struct Gate {
    reached: Option<mpsc::Receiver<()>>,
    release: mpsc::Sender<()>,
}

impl Gate {
    /// Holds the next request `method path` of `fake`.
    fn hold(fake: &Fake, method: &str, path: &str) -> Gate {
        let (reached_tx, reached) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        fake.with(|s| s.pause = Some((method.into(), path.into(), reached_tx, release_rx)));
        Gate { reached: Some(reached), release }
    }

    /// Returns once the server holds the request.
    async fn arrived(&mut self) {
        let reached = self.reached.take().unwrap();
        tokio::task::spawn_blocking(move || reached.recv().unwrap()).await.unwrap();
    }

    fn open(self) {
        self.release.send(()).unwrap();
    }
}

/// Holds the request `method path`, locks the keyring while it is in flight,
/// and then lets the request go. Returns what `op` returned.
async fn lock_during<T: 'static>(
    v: &Vault,
    method: &str,
    path: &str,
    op: impl std::future::Future<Output = T> + 'static,
) -> T {
    let mut gate = Gate::hold(&v.fake, method, path);
    // The core's futures are not `Send`: `op` runs on this thread.
    let local = tokio::task::LocalSet::new();
    let running = local.spawn_local(op);
    local.run_until(gate.arrived()).await;
    // `lock` drops the keys at once, then waits for the request in flight to
    // log out.
    let backend = v.backend.clone();
    let locking = tokio::spawn(async move { backend.lock().await });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while v.backend.state.lock().await.is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("lock drops the keys");
    gate.open();
    let out = local.run_until(running).await.unwrap();
    locking.await.unwrap();
    out
}

/// A vault with the login `gh` (cipher `c1`), whose first write back this
/// device already confirmed (ADR 0016).
async fn github() -> Vault {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
    v.confirm_write_back("gh", "c1").await;
    v
}

#[tokio::test]
async fn a_server_that_cannot_take_a_write_now_gets_it_later() {
    // 401: the session ended; 429 and 500: the server is busy or broken.
    for status in [401u16, 429, 500] {
        let v = github().await;
        v.fake.fault("PUT", "/api/ciphers/c1", status, 1);
        let item = ItemData { label: "Mine".into(), ..v.item_offline("gh").await };
        v.backend.put_item(&item).await.unwrap();
        assert_eq!(v.queue_sizes().await, (1, 1), "{status}");
        assert_eq!(v.item_offline("gh").await.label, "Mine", "{status}");
        assert_eq!(v.logged_in().await, status != 401, "{status}: an ended session is dropped");

        // Later it goes through, after a new login when one is needed.
        v.backend.refresh().await.unwrap();
        assert_eq!(v.queue_sizes().await, (0, 0), "{status}");
        assert_eq!(v.marked("c1").item.label, "Mine", "{status}");
    }
}

#[tokio::test]
async fn a_server_that_refuses_a_write_is_not_asked_again() {
    for status in [400u16, 404] {
        let v = github().await;
        v.fake.fault("PUT", "/api/ciphers/c1", status, 1);
        let item = ItemData { label: "Mine".into(), ..v.item_offline("gh").await };
        let err = v.backend.put_item(&item).await.unwrap_err();
        let shown = format!("HTTP {status}");
        assert!(matches!(&err, BackendError::Rejected(m) if m.contains(&shown)), "{err}");
        assert_eq!(v.queue_sizes().await, (0, 0), "{status}");
        assert!(!v.names("c1").iter().any(|n| n == "bwss:label"), "{status}: nothing was written");
        assert_eq!(v.item_offline("gh").await.label, "gh", "{status}: the refused change is not shown");
    }
}

#[tokio::test]
async fn a_refused_write_shows_the_server_copy_again() {
    // Another device labelled the item; this one has not seen it yet.
    let v = github().await;
    v.add_field("c1", "bwss:label", "Elsewhere");
    v.fake.fault("PUT", "/api/ciphers/c1", 400, 1);
    let item = ItemData { label: "Mine".into(), ..v.item_offline("gh").await };
    assert!(matches!(v.backend.put_item(&item).await, Err(BackendError::Rejected(_))));
    assert_eq!(v.item_offline("gh").await.label, "Elsewhere");

    // The item was removed meanwhile.
    let v = github().await;
    v.fake.fault("PUT", "/api/ciphers/c1", 400, 1);
    v.fake.fault("GET", "/api/ciphers/c1", 404, 1);
    let item = ItemData { label: "Mine".into(), ..v.item_offline("gh").await };
    assert!(matches!(v.backend.put_item(&item).await, Err(BackendError::Rejected(_))));
    assert!(!v.has_item("gh").await);

    // The server cannot be asked again: the view stays as it was.
    let v = github().await;
    v.fake.fault("PUT", "/api/ciphers/c1", 400, 1);
    v.fake.fault("GET", "/api/ciphers/c1", 500, 1);
    let item = ItemData { label: "Mine".into(), ..v.item_offline("gh").await };
    assert!(matches!(v.backend.put_item(&item).await, Err(BackendError::Rejected(_))));
    assert_eq!(v.item_offline("gh").await.label, "gh");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_keyring_locked_before_the_reread_stays_locked() {
    let v = github().await;
    v.fake.fault("PUT", "/api/ciphers/c1", 400, 1);
    let item = ItemData { label: "Mine".into(), ..v.item_offline("gh").await };
    let backend = v.backend.clone();
    let result = lock_during(&v, "GET", "/api/ciphers/c1", async move { backend.put_item(&item).await }).await;
    assert!(matches!(&result, Err(BackendError::Rejected(m)) if m.contains("HTTP 400")), "{result:?}");
    assert!(v.backend.state.lock().await.is_none(), "the reread does not bring the keyring back");
    assert_eq!(v.queued().await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_after_a_lock_is_told_the_keyring_is_locked() {
    // The folder is created while the keyring locks; the note is not.
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    let backend = v.backend.clone();
    let result =
        lock_during(&v, "POST", "/api/folders", async move { backend.put_item(&new_item("n1", "login")).await }).await;
    assert!(matches!(result, Err(BackendError::Locked)), "{result:?}");
    assert_eq!(v.fake.count("POST", "/api/folders"), 1);
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flush_stops_when_the_keyring_locks_and_the_write_stays_on_disk() {
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    v.fake.with(|s| s.down = true);
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    assert_eq!(v.queue_file(), 1);
    v.fake.with(|s| s.down = false);

    let backend = v.backend.clone();
    let result = lock_during(&v, "POST", "/api/folders", async move { backend.refresh().await }).await;
    assert!(matches!(result, Err(BackendError::Locked)), "{result:?}");
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 0, "nothing was created");
    assert_eq!(v.queue_file(), 1, "the create waits on disk for the next unlock");
    v.backend.unlock(PASSWORD).await.unwrap();
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1, "and goes out then");
}

// --- deleting ----------------------------------------------------------------------

const MARKS: [&str; 3] = ["bwss:id", "bwss:attr:service", "obsidian:id"];

#[tokio::test]
async fn a_delete_of_an_item_that_left_the_server_sends_nothing_more() {
    let v = github().await;
    // The save is out of date, and the item cannot be fetched any more.
    v.fake.with(|s| s.stale_puts = 1);
    v.fake.fault("GET", "/api/ciphers/c1", 404, 1);
    let item = v.item_offline("gh").await;
    v.backend.delete_item(&item).await.unwrap();
    assert_eq!(v.fake.count("PUT", "/api/ciphers/c1"), 1);
    assert_eq!(v.names("c1"), MARKS, "the server's copy is not touched");
}

#[tokio::test]
async fn a_delete_that_cannot_refetch_the_item_is_queued() {
    let v = github().await;
    v.fake.with(|s| s.stale_puts = 1);
    v.fake.fault("GET", "/api/ciphers/c1", 500, 1);
    let item = v.item_offline("gh").await;
    v.backend.delete_item(&item).await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1));
    // Back to normal: the delete goes through.
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert_eq!(v.names("c1"), ["obsidian:id"]);
}

#[tokio::test]
async fn a_delete_whose_answer_cannot_be_read_keeps_the_item() {
    let v = github().await;
    let unreadable = json!({
        "id": "c1", "type": 1, "revisionDate": REV,
        "fields": [{ "type": 0, "name": "2.bad|bad|bad", "value": "2.bad|bad|bad" }],
    });
    v.fake.fault_reply("PUT", "/api/ciphers/c1", 200, unreadable);
    let item = v.item_offline("gh").await;
    v.backend.delete_item(&item).await.unwrap();
    assert_eq!(v.fake.count("PUT", "/api/ciphers/c1/delete"), 0, "what cannot be read is never trashed");
    assert!(v.fake.cipher("c1")["deletedDate"].is_null());
}

#[tokio::test]
async fn an_item_left_in_the_vault_when_the_trash_refuses_it_is_no_longer_the_keyrings() {
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    let cid = v.fake.with(|s| s.sync["ciphers"][0]["id"].as_str().unwrap().to_owned());
    v.fake.fault("PUT", &format!("/api/ciphers/{cid}/delete"), 500, 1);
    let item = v.item("n1").await;
    v.backend.delete_item(&item).await.unwrap();
    assert!(v.fake.cipher(&cid)["deletedDate"].is_null(), "still in the vault, as a bare note");
    assert!(v.names(&cid).is_empty(), "with none of bwss's fields");
    assert!(!v.has_item("n1").await);
    assert_eq!(v.queued().await, 0);
}

#[tokio::test]
async fn a_delete_that_keeps_meeting_changes_is_told_to_try_again() {
    let v = github().await;
    v.fake.with(|s| s.stale_puts = 3);
    let item = v.item_offline("gh").await;
    let err = v.backend.delete_item(&item).await.unwrap_err();
    assert!(matches!(&err, BackendError::Unavailable(m) if m.ends_with("try again")), "{err}");
    assert_eq!((v.queued().await, v.names("c1")), (0, MARKS.map(String::from).to_vec()));
}

#[tokio::test]
async fn a_delete_gives_way_to_what_another_device_did_to_the_item() {
    // It was unmarked meanwhile: it has left the keyring by itself.
    let v = github().await;
    v.fake.with(|s| s.before_put = Some(Box::new(|c: &mut Value| c["fields"] = json!([]))));
    let item = v.item_offline("gh").await;
    v.backend.delete_item(&item).await.unwrap();
    assert_eq!(v.fake.count("PUT", "/api/ciphers/c1"), 1, "only the out-of-date save");
    assert!(v.names("c1").is_empty());

    // It cannot be read now: the app is told to try again, nothing is queued.
    let v = github().await;
    v.fake.with(|s| s.before_put = Some(Box::new(|c: &mut Value| c["key"] = json!("2.AAAA|AAAA|AAAA"))));
    let item = v.item_offline("gh").await;
    let err = v.backend.delete_item(&item).await.unwrap_err();
    assert!(
        matches!(&err, BackendError::Unavailable(m) if m.contains("c1") && m.ends_with("try again later")),
        "{err}"
    );
    assert_eq!(v.queued().await, 0);

    // Its answer has no revision: it cannot be stripped safely.
    let v = github().await;
    v.fake.with(|s| s.stale_puts = 1);
    let mut no_revision = v.fake.cipher("c1");
    no_revision.as_object_mut().unwrap().remove("revisionDate");
    v.fake.fault_reply("GET", "/api/ciphers/c1", 200, no_revision);
    let item = v.item_offline("gh").await;
    let err = v.backend.delete_item(&item).await.unwrap_err();
    // The core reads a copy without a revision as one it cannot read now.
    assert!(
        matches!(&err, BackendError::Unavailable(m) if m.starts_with("c1: ") && m.ends_with("try again later")),
        "{err}"
    );
    assert_eq!(v.names("c1"), MARKS, "nothing was stripped");
}

#[tokio::test]
async fn a_queued_delete_waits_for_an_item_that_cannot_be_read() {
    let v = github().await;
    v.fake.with(|s| s.down = true);
    let item = v.item_offline("gh").await;
    v.backend.delete_item(&item).await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1));

    // The key of the item no longer unwraps. The first flush finds out when
    // its save is out of date; the second one knows the item as held.
    let good_key = v.fake.cipher("c1")["key"].clone();
    let puts = v.fake.count("PUT", "/api/ciphers/c1");
    v.fake.with(|s| s.down = false);
    v.edit_elsewhere("c1", |c| c["key"] = json!("2.AAAA|AAAA|AAAA"));
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1), "the delete waits");
    assert_eq!(v.fake.count("PUT", "/api/ciphers/c1") - puts, 1, "only the out-of-date save, never sent again");

    v.edit_elsewhere("c1", |c| c["key"] = good_key);
    v.backend.refresh().await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert_eq!(v.names("c1"), ["obsidian:id"]);
}

#[tokio::test]
async fn a_cipher_that_turns_blob_encrypted_is_held_not_deleted_or_recreated() {
    let v = github().await;
    let posts = v.fake.count("POST", "/api/ciphers");
    let blob = r#"{"format_version":1,"wrapped_cek":"2.x|y|z","envelope":"AAAA"}"#;
    v.edit_elsewhere("c1", |c| {
        c["data"] = json!(blob);
        for f in ["name", "notes", "login", "fields"] {
            c[f] = Value::Null;
        }
    });
    v.backend.refresh().await.unwrap();
    v.backend.refresh().await.unwrap();
    let ids: Vec<_> = v.snapshot().await.items.into_iter().map(|i| i.id).collect();
    assert_eq!(ids, ["gh"], "still present as last read");

    let item = ItemData { label: "Mine".into(), ..v.item_offline("gh").await };
    let err = v.backend.put_item(&item).await.unwrap_err();
    assert!(matches!(&err, BackendError::Unavailable(m) if m.contains("cannot be read now")), "{err}");
    assert_eq!(v.fake.count("POST", "/api/ciphers"), posts, "never recreated");
    assert_eq!(v.queued().await, 0);
}

#[tokio::test]
async fn blob_ciphers_are_listed_after_an_unlock_and_counted_in_the_status() {
    let v = github().await;
    assert_eq!(v.snapshot().await.ciphers.get("gh").map(String::as_str), Some("c1"));
    v.edit_elsewhere("c1", |c| {
        c["data"] = json!(r#"{"format_version":1}"#);
        for f in ["name", "notes", "login", "fields"] {
            c[f] = Value::Null;
        }
    });
    v.backend.lock().await;
    v.backend.unlock(PASSWORD).await.unwrap();
    let snap = v.snapshot().await;
    assert!(snap.items.is_empty());
    // B4: the core reads blobs; one that does not open is held like any
    // uninspectable cipher, and the old blob count left the status.
    assert_eq!(snap.held.into_iter().collect::<Vec<_>>(), ["c1"]);
    let status = v.backend.describe().await;
    assert!(!status.contains("newer encryption format") && !status.contains("c1"), "{status}");
}

#[tokio::test]
async fn writes_to_an_item_that_cannot_be_read_wait() {
    let v = github().await;
    v.edit_elsewhere("c1", |c| c["key"] = json!("2.AAAA|AAAA|AAAA"));
    v.backend.refresh().await.unwrap();
    let item = ItemData { label: "Mine".into(), ..v.item_offline("gh").await };

    let err = v.backend.put_item(&item).await.unwrap_err();
    assert!(
        matches!(&err, BackendError::Unavailable(m) if m.contains("cannot be read now") && m.ends_with("try again later")),
        "{err}"
    );
    assert_eq!(v.queued().await, 0);

    let err = v.backend.delete_item(&item).await.unwrap_err();
    assert!(matches!(&err, BackendError::Unavailable(m) if m.contains("cannot be read now")), "{err}");

    // With the session gone and the server down, it is queued, to be applied
    // once the item can be read.
    *v.backend.client.lock().await = None;
    v.fake.with(|s| s.down = true);
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1));
}

#[tokio::test]
async fn a_queued_write_the_server_refuses_is_dropped_and_the_view_goes_back() {
    let v = github().await;
    v.fake.with(|s| s.down = true);
    let item = ItemData { label: "Queued".into(), ..v.item_offline("gh").await };
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1));
    v.fake.with(|s| s.down = false);
    v.fake.fault("PUT", "/api/ciphers/c1", 400, 1);
    let puts = v.fake.count("PUT", "/api/ciphers/c1");

    // The vault did not change, but what is shown did: the change is gone.
    let shown = v.backend.refresh().await.unwrap().expect("the view changed");
    assert_eq!(shown.items[0].label, "gh");
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert_eq!(v.fake.count("PUT", "/api/ciphers/c1") - puts, 1, "refused once, not sent again");
    assert!(!v.names("c1").iter().any(|n| n == "bwss:label"));
}

#[tokio::test]
async fn ops_that_were_done_before_send_nothing() {
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    let item = v.item("n1").await;
    let (posts, puts) = (v.fake.count("POST", "/api/ciphers"), v.fake.count("PUT", "/api/ciphers"));

    // A queued create that was accepted before (just before a lock).
    let create = Op::Create(new_item_of(&item, None));
    let effect = v.backend.run(&Queue::default(), &create).await.unwrap();
    assert!(matches!(effect, Effect::Nothing), "{effect:?}");

    // A patch with no change.
    let empty = Op::Patch(Patch {
        id: "n1".into(),
        cipher_id: None,
        organization_id: None,
        base_revision: REV.into(),
        set: vec![],
        remove: vec![],
        append_lines: vec![],
        value: ValueChange::Keep,
        answer: None,
    });
    let effect = v.backend.run(&Queue::default(), &empty).await.unwrap();
    assert!(matches!(effect, Effect::Nothing), "{effect:?}");
    assert_eq!((v.fake.count("POST", "/api/ciphers"), v.fake.count("PUT", "/api/ciphers")), (posts, puts));
}

#[tokio::test]
async fn a_new_item_the_server_refuses_is_rejected() {
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    v.fake.fault("POST", "/api/ciphers", 400, 1);
    let err = v.backend.put_item(&new_item("n1", "login")).await.unwrap_err();
    assert!(matches!(&err, BackendError::Rejected(m) if m.contains("HTTP 400")), "{err}");
    assert!(!v.has_item("n1").await);
    assert_eq!(v.queue_sizes().await, (0, 0));
}

#[tokio::test]
async fn a_folder_the_server_creates_without_an_id_is_not_used_yet() {
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    v.fake.fault_reply("POST", "/api/folders", 200, json!({ "name": "x" }));
    // A server that answers oddly is treated as one that cannot be used now.
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1));
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 0);
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1, "and the folder is made properly the next time");
}

#[tokio::test]
async fn a_new_item_queued_offline_is_edited_and_dropped_in_the_queue() {
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    v.fake.with(|s| s.down = true);
    let mut item = new_item("n1", "login");
    v.backend.put_item(&item).await.unwrap();

    // The app edits it before it ever reached the server: one create, the last version.
    item.label = "Renamed".into();
    item.collection = "work".into();
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1));
    let shown = v.item_offline("n1").await;
    assert_eq!((shown.label.as_str(), shown.collection.as_str()), ("Renamed", "work"));

    // A version that could never be written is refused, and the queue keeps the last good one.
    item.attributes.insert("blob".into(), "x".repeat(5_000));
    let err = v.backend.put_item(&item).await.unwrap_err();
    assert!(matches!(err, BackendError::Rejected(_)), "{err}");
    assert_eq!(v.queue_sizes().await, (1, 1));
    assert!(!v.item_offline("n1").await.attributes.contains_key("blob"));

    // A second item is created and deleted before the server was reachable.
    let second = new_item("n2", "login");
    v.backend.put_item(&second).await.unwrap();
    assert_eq!(v.queue_sizes().await, (2, 2));
    v.backend.delete_item(&second).await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1));
    assert!(!v.has_item("n2").await);

    v.fake.with(|s| s.down = false);
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1, "n2 never reached the server");
    let cid = v.fake.with(|s| s.sync["ciphers"][0]["id"].as_str().unwrap().to_owned());
    let created = v.marked(&cid).item;
    assert_eq!((created.id.as_str(), created.label.as_str(), created.collection.as_str()), ("n1", "Renamed", "work"));
}

// --- collections ---------------------------------------------------------------------

const HOME: &str = r#"{"home":{"label":"Home","created":1}}"#;

async fn with_registry() -> Vault {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    vault(vec![registry_note(&k, "r1", HOME)], k).await
}

/// The collections in the registry note that is not `r1`, the last cipher.
fn newest_registry(v: &Vault) -> Registry {
    let note = v.fake.with(|s| s.sync["ciphers"].as_array().unwrap().last().unwrap().clone());
    Registry::try_parse(&v.dec(&note["notes"])).unwrap()
}

#[tokio::test]
async fn a_collection_change_that_keeps_meeting_changes_is_told_to_try_again() {
    let v = with_registry().await;
    v.fake.with(|s| s.stale_puts = 3);
    let err = v.backend.create_collection("Work").await.unwrap_err();
    assert!(
        matches!(&err, BackendError::Unavailable(m) if m.contains("registry keeps changing") && m.ends_with("try again")),
        "{err}"
    );
    assert_eq!(v.queued().await, 0);
}

#[tokio::test]
async fn a_registry_note_that_left_the_server_is_written_anew() {
    let v = with_registry().await;
    v.fake.with(|s| s.stale_puts = 1);
    v.fake.fault("GET", "/api/ciphers/r1", 404, 1);
    v.backend.create_collection("Work").await.unwrap();
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1);
    let ids: Vec<_> = newest_registry(&v).0.into_keys().collect();
    assert_eq!(ids, ["home", "work"]);
}

#[tokio::test]
async fn a_collection_change_that_cannot_refetch_the_note_is_queued() {
    let v = with_registry().await;
    v.fake.with(|s| s.stale_puts = 1);
    v.fake.fault("GET", "/api/ciphers/r1", 500, 1);
    v.backend.create_collection("Work").await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1));
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert!(Registry::try_parse(&v.dec(&v.fake.cipher("r1")["notes"])).unwrap().0.contains_key("work"));
}

#[tokio::test]
async fn a_registry_note_changed_elsewhere_into_something_else_is_handled() {
    // Its key no longer unwraps.
    let v = with_registry().await;
    v.fake.with(|s| s.before_put = Some(Box::new(|c: &mut Value| c["key"] = json!("2.AAAA|AAAA|AAAA"))));
    let err = v.backend.create_collection("Work").await.unwrap_err();
    assert!(
        matches!(&err, BackendError::Unavailable(m) if m.contains("r1") && m.ends_with("try again later")),
        "{err}"
    );

    // Its notes are no longer a registry: never written over.
    let v = with_registry().await;
    let junk = v.keys.user.encrypt_str("not json", &OsRandom).unwrap();
    v.fake.with(|s| s.before_put = Some(Box::new(move |c: &mut Value| c["notes"] = json!(junk))));
    let err = v.backend.create_collection("Work").await.unwrap_err();
    assert!(
        matches!(&err, BackendError::Unavailable(m) if m.starts_with("the collection registry cannot be read")),
        "{err}"
    );
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 0);

    // It is no longer of the registry's kind: a new registry note is started.
    let v = with_registry().await;
    let (name, other) = (
        v.keys.user.encrypt_str("bwss:kind", &OsRandom).unwrap(),
        v.keys.user.encrypt_str("something-else", &OsRandom).unwrap(),
    );
    v.fake.with(|s| {
        // The second field is `bwss:kind`.
        s.before_put =
            Some(Box::new(move |c: &mut Value| c["fields"][1] = json!({ "type": 0, "name": name, "value": other })))
    });
    v.backend.create_collection("Work").await.unwrap();
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1);

    // It lost its marks: a new registry note is started, with what is known.
    let v = with_registry().await;
    v.fake.with(|s| s.before_put = Some(Box::new(|c: &mut Value| c["fields"] = json!([]))));
    v.backend.create_collection("Work").await.unwrap();
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1);
    assert_eq!(newest_registry(&v).0.into_keys().collect::<Vec<_>>(), ["home", "work"]);
}

#[tokio::test]
async fn a_registry_note_with_a_password_field_is_never_rewritten() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let mut note = registry_note(&k, "r1", HOME);
    note["fields"] = enc_fields(
        &k,
        &[("bwss:id", "_collections"), ("bwss:kind", "collections"), ("bwss:password", "binary registry")],
    );
    let v = vault(vec![note], k).await;
    let err = v.backend.create_collection("Work").await.unwrap_err();
    assert!(matches!(&err, BackendError::Unavailable(m) if m.contains("bwss:password field")), "{err}");
    assert_eq!(v.fake.count("PUT", "/api/ciphers/"), 0);
}

#[tokio::test]
async fn a_registry_note_the_server_refuses_is_rejected() {
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    v.fake.fault("POST", "/api/ciphers", 400, 1);
    let err = v.backend.create_collection("Work").await.unwrap_err();
    assert!(matches!(&err, BackendError::Rejected(m) if m.contains("HTTP 400")), "{err}");
    assert_eq!(v.queued().await, 0);
}

#[tokio::test]
async fn a_queued_collection_change_waits_for_a_registry_that_cannot_be_read() {
    let v = with_registry().await;
    v.fake.with(|s| s.down = true);
    v.backend.create_collection("Work").await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1));

    // Another device wrote something else into the registry note.
    v.fake.with(|s| s.down = false);
    let puts = v.fake.count("PUT", "/api/ciphers/r1");
    let junk = v.keys.user.encrypt_str("not json", &OsRandom).unwrap();
    v.edit_elsewhere("r1", |c| c["notes"] = json!(junk));
    v.backend.refresh().await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1), "never written over, never dropped");
    assert_eq!(v.fake.count("PUT", "/api/ciphers/r1") - puts, 1, "only the out-of-date attempt");

    // Fixed: the change goes through.
    let fixed = v.keys.user.encrypt_str(HOME, &OsRandom).unwrap();
    v.edit_elsewhere("r1", |c| c["notes"] = json!(fixed));
    v.backend.refresh().await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert!(Registry::try_parse(&v.dec(&v.fake.cipher("r1")["notes"])).unwrap().0.contains_key("work"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registry_found_unreadable_while_its_folder_is_made_is_not_written() {
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    let mut gate = Gate::hold(&v.fake, "POST", "/api/folders");
    let backend = v.backend.clone();
    let local = tokio::task::LocalSet::new();
    let creating = local.spawn_local(async move { backend.create_collection("Work").await });
    local.run_until(gate.arrived()).await;
    // The keyring is rebuilt meanwhile, and the registry is now unreadable.
    v.backend.state.lock().await.as_mut().unwrap().built.registry_unreadable = true;
    gate.open();
    let err = local.run_until(creating).await.unwrap().unwrap_err();
    assert!(
        matches!(&err, BackendError::Unavailable(m) if m.starts_with("the collection registry cannot be read")),
        "{err}"
    );
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 0);
}

// --- unlocking -----------------------------------------------------------------------

#[tokio::test]
async fn an_unlock_that_cannot_go_on_says_why() {
    let v = github().await;
    let account_key = v.fake.with(|s| s.sync["profile"]["key"].clone());
    v.backend.lock().await;

    // A refusal is not an outage: the offline copy is not used.
    v.fake.fault("POST", "/identity/connect/token", 401, 1);
    let err = v.backend.unlock(PASSWORD).await.unwrap_err();
    assert!(matches!(&err, BackendError::Rejected(m) if m.contains("HTTP 401")), "{err}");
    v.fake.fault("POST", "/identity/accounts/prelogin", 400, 1);
    let err = v.backend.unlock(PASSWORD).await.unwrap_err();
    assert!(matches!(&err, BackendError::Rejected(m) if m.contains("HTTP 400")), "{err}");

    v.fake.with(|s| s.sync["profile"]["key"] = Value::Null);
    let err = v.backend.unlock(PASSWORD).await.unwrap_err();
    // The core refuses such a `/sync` as a protocol error: the server is wrong, not away.
    assert!(matches!(&err, BackendError::Rejected(m) if m.contains("no account key")), "{err}");
    v.fake.with(|s| s.sync["profile"]["key"] = account_key);

    // A key derivation the client refuses to run.
    v.fake.fault_reply("POST", "/identity/accounts/prelogin", 200, json!({ "kdf": 0, "kdfIterations": 0 }));
    let err = v.backend.unlock(PASSWORD).await.unwrap_err();
    assert!(matches!(err, BackendError::Rejected(_)), "{err}");
    assert!(v.backend.state.lock().await.is_none());

    // Nothing is reachable and nothing is cached.
    std::fs::remove_file(v.dir.join("cache/sync.json")).unwrap();
    v.fake.with(|s| s.down = true);
    let err = v.backend.unlock(PASSWORD).await.unwrap_err();
    assert!(matches!(&err, BackendError::Unavailable(m) if m.contains("no offline copy yet")), "{err}");

    // Reachable again: all is well.
    v.fake.with(|s| s.down = false);
    assert_eq!(v.backend.unlock(PASSWORD).await.unwrap().items.len(), 1);
}

#[tokio::test]
async fn a_cache_that_cannot_be_written_does_not_stop_the_unlock() {
    let v = github().await;
    v.backend.lock().await;
    let cache = v.dir.join("cache/sync.json");
    std::fs::remove_file(&cache).unwrap();
    // The private write goes through this temporary name.
    std::fs::create_dir_all(crate::fsutil::temp_path(&cache)).unwrap();
    assert_eq!(v.backend.unlock(PASSWORD).await.unwrap().items.len(), 1);
    assert!(!cache.exists(), "no offline copy was made");
}

#[tokio::test]
async fn status_lists_items_that_are_not_supported() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let mut card = hand_marked(&k, "c4", "card");
    card["type"] = json!(3);
    let v = vault(vec![hand_marked(&k, "c1", "gh"), card], k).await;
    let status = v.backend.describe().await;
    assert!(status.contains("\nskipped: c4: its item type is not supported"), "{status}");
}

#[tokio::test]
async fn an_offline_unlock_uses_only_the_cache_of_its_own_account() {
    let v = github().await;
    v.backend.lock().await;
    v.fake.with(|s| s.down = true);
    assert_eq!(v.backend.unlock(PASSWORD).await.unwrap().items.len(), 1, "the cached vault opens");

    v.backend.lock().await;
    let cache = v.dir.join("cache/sync.json");
    let mut doc: Value = serde_json::from_slice(&std::fs::read(&cache).unwrap()).unwrap();
    doc["email"] = json!("other@example.org");
    std::fs::write(&cache, serde_json::to_vec(&doc).unwrap()).unwrap();
    let err = v.backend.unlock(PASSWORD).await.unwrap_err();
    assert!(matches!(&err, BackendError::Unavailable(m) if m.contains("no offline copy yet")), "{err}");
}

#[test]
fn the_device_id_is_made_once_and_kept() {
    let config = Config {
        server_url: "http://127.0.0.1:1".into(),
        email: EMAIL.into(),
        profile: Some("p".into()),
        ..Config::default()
    };
    let creds = || Credentials {
        identity_origin: "http://127.0.0.1:1".into(),
        client_id: "id".into(),
        client_secret: Zeroizing::new("secret".into()),
    };
    let dir = tempfile::tempdir().unwrap();
    let paths = paths_in(dir.path());
    let device = paths.device_id("p");
    BitwardenBackend::new(&config, creds(), &paths).unwrap();
    let first = std::fs::read_to_string(&device).unwrap();
    assert_eq!(first.len(), 36, "a UUID: {first:?}");
    BitwardenBackend::new(&config, creds(), &paths).unwrap();
    assert_eq!(std::fs::read_to_string(&device).unwrap(), first, "the same device next time");

    // A blank file is no id: a new one is made.
    std::fs::write(&device, "  \n").unwrap();
    BitwardenBackend::new(&config, creds(), &paths).unwrap();
    assert_eq!(std::fs::read_to_string(&device).unwrap().len(), 36);
}

#[tokio::test]
async fn a_server_answer_without_an_id_is_not_recorded() {
    let v = github().await;
    v.fake.fault_reply("PUT", "/api/ciphers/c1", 200, json!({ "object": "cipherDetails" }));
    let item = ItemData { label: "Mine".into(), ..v.item_offline("gh").await };
    v.backend.put_item(&item).await.unwrap();
    let cached = v.backend.state.lock().await.as_ref().unwrap().sync["ciphers"].as_array().unwrap().len();
    assert_eq!(cached, 1, "nothing was added to the cached vault");
    assert_eq!(v.item_offline("gh").await.label, "gh");
}

#[tokio::test]
async fn a_vault_sync_without_a_cipher_list_still_takes_writes() {
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    v.fake.with(|s| {
        s.rev += 1;
        s.sync.as_object_mut().unwrap().remove("ciphers");
    });
    v.backend.refresh().await.unwrap();
    // The core's client reads a missing list as an empty one.
    assert_eq!(v.backend.state.lock().await.as_ref().unwrap().sync["ciphers"], json!([]));
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1);
    // The server's answer had nowhere to go in the cache: the next sync shows the item.
    assert_eq!(v.item("n1").await.label, "App token");
}

#[tokio::test]
async fn deleting_a_collection_that_only_items_name_leaves_no_registry_entry() {
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    v.backend.put_item(&new_item("n1", "work")).await.unwrap();
    v.snapshot().await;
    v.backend.delete_collection("work", &["n1".to_owned()]).await.unwrap();
    let snap = v.snapshot().await;
    assert!(snap.items.is_empty());
    assert!(!snap.collections.iter().any(|c| c.id == "work"));
    // The one cipher is the item's, now a bare note in the trash; no registry note was written.
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1);
}

#[test]
fn a_backend_needs_a_profile_to_serve() {
    let config = Config { server_url: "http://127.0.0.1:1".into(), email: EMAIL.into(), ..Config::default() };
    let creds = Credentials {
        identity_origin: "http://127.0.0.1:1".into(),
        client_id: "id".into(),
        client_secret: Zeroizing::new("secret".into()),
    };
    let dir = tempfile::tempdir().unwrap();
    let err = BitwardenBackend::new(&config, creds, &paths_in(dir.path())).err().unwrap();
    assert_eq!(err.to_string(), "no profile to serve");
}

#[tokio::test]
async fn a_new_item_too_large_for_bitwarden_is_rejected_when_it_is_sent() {
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    let mut item = new_item("n1", "login");
    item.attributes.insert("blob".into(), "x".repeat(5_000));
    let err = v.backend.put_item(&item).await.unwrap_err();
    assert!(matches!(&err, BackendError::Rejected(m) if m.contains("too large")), "{err}");
    assert_eq!((v.fake.count("POST", "/api/ciphers"), v.queued().await), (0, 0));
    assert!(!v.has_item("n1").await);
}

#[tokio::test]
async fn a_collection_too_large_for_the_registry_note_is_rejected() {
    let big = "x".repeat(20_000);
    // Changing the registry note that exists.
    let v = with_registry().await;
    let err = v.backend.create_collection(&big).await.unwrap_err();
    assert!(matches!(&err, BackendError::Rejected(m) if m.contains("too large")), "{err}");
    assert_eq!(v.fake.count("PUT", "/api/ciphers/r1"), 0);
    // Writing the first one.
    let v = vault(vec![], SymmetricKey::generate(&OsRandom).unwrap()).await;
    let err = v.backend.create_collection(&big).await.unwrap_err();
    assert!(matches!(&err, BackendError::Rejected(m) if m.contains("too large")), "{err}");
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 0);
    assert_eq!(v.queued().await, 0);
}

#[tokio::test]
async fn a_collection_made_again_is_newer_than_its_tombstone() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let far = crate::model::now() + 1_000_000;
    let tombstone = format!(r#"{{"work":{{"label":"Old","created":{far},"deleted":true}}}}"#);
    let v = vault(vec![registry_note(&k, "r1", &tombstone)], k).await;
    let work = v.backend.create_collection("Work").await.unwrap();
    assert_eq!((work.id.as_str(), work.created), ("work", far + 1));
    let registry = Registry::try_parse(&v.dec(&v.fake.cipher("r1")["notes"])).unwrap();
    assert!(!registry.0["work"].deleted);
    assert_eq!(registry.0["work"].created, far + 1);
}

#[tokio::test]
async fn collections_are_written_to_the_registry_note_with_the_lowest_id() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let notes = [registry_note(&k, "r2", HOME), registry_note(&k, "r1", HOME)];
    let v = vault(notes.to_vec(), k).await;
    v.backend.create_collection("Work").await.unwrap();
    let registry = |cid: &str| Registry::try_parse(&v.dec(&v.fake.cipher(cid)["notes"])).unwrap();
    assert!(registry("r1").0.contains_key("work"));
    assert!(!registry("r2").0.contains_key("work"), "the other note is left as it was");
}

#[tokio::test]
async fn a_registry_that_cannot_be_inspected_keeps_its_collections_while_changes_wait() {
    let v = with_registry().await;
    v.fake.with(|s| s.down = true);
    v.backend.create_collection("Work").await.unwrap();
    v.fake.with(|s| s.down = false);
    v.edit_elsewhere("r1", |c| c["key"] = json!("2.AAAA|AAAA|AAAA"));
    v.backend.refresh().await.unwrap();
    let ids: Vec<_> = v.snapshot().await.collections.into_iter().map(|c| c.id).collect();
    assert_eq!(ids, ["home", "login", "work"], "the registry as last read, with the queued collection");
    assert_eq!(v.queue_sizes().await, (1, 1), "and the change waits");
    assert!(v.backend.describe().await.contains("collection registry cannot be read"));
}

/// The handle the daemon sees, unlocked, on its worker thread.
async fn handle(ciphers: Vec<Value>) -> (Fake, BitwardenBackend, tempfile::TempDir) {
    let (fake, config, creds, paths, dir) = server(ciphers, &SymmetricKey::generate(&OsRandom).unwrap());
    let backend = BitwardenBackend::new(&config, creds, &paths).unwrap();
    backend.unlock(PASSWORD).await.unwrap();
    (fake, backend, dir)
}

const STOPPED: &str = "bwss's vault worker stopped; it was restarted locked";

#[tokio::test]
async fn commands_round_trip() {
    let (_fake, b, _dir) = handle(vec![]).await;
    assert!(matches!(b.unlock("wrong").await, Err(BackendError::WrongPassword)));
    let answer = (HistoryQuestion::FirstWriteBack, HistoryAnswer::WriteToLogin);
    b.put_item_answered(&new_item("n1", "login"), answer).await.unwrap();
    assert!(b.queued_question("n1").await.unwrap().is_none());
    assert!(matches!(b.answer_queued("n1", answer.0, None).await, Err(BackendError::Rejected(_))));
    let work = b.create_collection("Work").await.unwrap();
    assert_eq!(work.id, "work");
    // The writes are already shown: nothing new on the server.
    assert!(b.refresh().await.unwrap().is_none());
    assert!(matches!(b.acl_trust().await, Ok(super::AclTrust::PerDevice(_))));
    assert!(b.describe().await.contains("0 queued change(s)"));
    b.delete_item(&new_item("n1", "login")).await.unwrap();
    b.delete_collection("work", &[]).await.unwrap();
    b.lock().await;
    assert!(matches!(b.acl_trust().await, Err(BackendError::Locked)));
    assert!(matches!(b.refresh().await, Err(BackendError::Locked)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_during_a_flush_wins() {
    let (fake, b, _dir) = handle(vec![]).await;
    fake.with(|s| s.down = true);
    b.put_item(&new_item("n1", "login")).await.unwrap();
    assert!(b.describe().await.contains("1 queued change(s)"));
    fake.with(|s| s.down = false);

    let b = Arc::new(b);
    let mut gate = Gate::hold(&fake, "POST", "/api/ciphers");
    let flushing = tokio::spawn({
        let b = b.clone();
        async move { b.refresh().await }
    });
    gate.arrived().await;
    // Handled between two awaits of the flush: the keys go at once.
    let locking = tokio::spawn({
        let b = b.clone();
        async move { b.lock().await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !matches!(b.acl_trust().await, Err(BackendError::Locked)) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("lock drops the keys while the flush waits on the server");
    gate.open();
    assert!(matches!(flushing.await.unwrap(), Err(BackendError::Locked)));
    locking.await.unwrap();
    assert!(b.describe().await.contains("0 queued change(s)"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_during_the_sync_of_a_refresh_clears_the_queue() {
    let (fake, b, _dir) = handle(vec![]).await;
    fake.with(|s| s.down = true);
    b.put_item(&new_item("n1", "login")).await.unwrap();
    fake.with(|s| s.down = false);
    // The queued create keeps failing and the server moved on: the refresh
    // reads the vault again, holding the queue.
    fake.fault("POST", "/api/ciphers", 503, 10);
    fake.with(|s| s.rev += 1);

    let b = Arc::new(b);
    let mut gate = Gate::hold(&fake, "GET", "/api/sync?excludeDomains=true");
    let refreshing = tokio::spawn({
        let b = b.clone();
        async move { b.refresh().await }
    });
    gate.arrived().await;
    let locking = tokio::spawn({
        let b = b.clone();
        async move { b.lock().await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !matches!(b.acl_trust().await, Err(BackendError::Locked)) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("lock drops the keys while the refresh waits on /sync");
    gate.open();
    assert!(matches!(refreshing.await.unwrap(), Err(BackendError::Locked)));
    locking.await.unwrap();
    // The queued plaintext left memory with the keys.
    assert!(b.describe().await.contains("0 queued change(s)"));
}

#[tokio::test]
async fn a_panicking_worker_fails_calls_instead_of_hanging() {
    let (_fake, b, _dir) = handle(vec![]).await;
    let panicked = tokio::time::timeout(std::time::Duration::from_secs(10), b.panic_for_test(false)).await;
    assert!(matches!(panicked, Ok(Err(BackendError::Unavailable(m))) if m == STOPPED));
    // The worker is still there for the next call.
    assert!(b.describe().await.starts_with("Bitwarden "));

    // A worker that is gone fails every call at once.
    let gone = BitwardenBackend::stopped_for_test();
    assert!(matches!(gone.unlock(PASSWORD).await, Err(BackendError::Unavailable(m)) if m == STOPPED));
    assert!(matches!(gone.refresh().await, Err(BackendError::Unavailable(_))));
    assert!(matches!(gone.create_collection("Work").await, Err(BackendError::Unavailable(_))));
    assert!(matches!(gone.delete_collection("work", &[]).await, Err(BackendError::Unavailable(_))));
    assert!(matches!(gone.put_item(&new_item("n1", "login")).await, Err(BackendError::Unavailable(_))));
    assert!(matches!(gone.delete_item(&new_item("n1", "login")).await, Err(BackendError::Unavailable(_))));
    assert!(matches!(gone.acl_trust().await, Err(BackendError::Unavailable(_))));
    gone.lock().await;
    assert_eq!(gone.describe().await, STOPPED);
    // A vault that panics while it is built never starts.
    assert!(super::worker::Worker::spawn(|| panic!("a test made the vault panic while it is built")).is_err());
}

#[tokio::test]
async fn calls_after_a_restart_see_a_locked_vault() {
    let (_fake, b, _dir) = handle(vec![]).await;
    assert!(b.acl_trust().await.is_ok());
    assert!(b.panic_for_test(false).await.is_err());
    assert!(matches!(b.acl_trust().await, Err(BackendError::Locked)));
    assert!(matches!(b.refresh().await, Err(BackendError::Locked)));
    b.unlock(PASSWORD).await.unwrap();
    assert!(b.acl_trust().await.is_ok());
}

/// A daemon over the vault worker, unlocked and holding item `n1`, that
/// follows the locks the worker makes by itself.
async fn daemon_on_the_worker() -> (Fake, Arc<crate::daemon::Daemon>, Arc<BitwardenBackend>, tempfile::TempDir) {
    let (fake, b, dir) = handle(vec![]).await;
    b.put_item(&new_item("n1", "login")).await.unwrap();
    let b = Arc::new(b);
    let prompter = crate::prompter::Prompter::new("false", std::time::Duration::from_secs(1));
    let d =
        crate::daemon::Daemon::new(crate::keyring::Keyring::new(None, None), b.clone(), prompter, Config::default());
    d.follow_backend_locks(b.locks());
    d.unlock_with_password(PASSWORD).await.unwrap();
    assert!(d.keyring.lock().await.item("n1").is_some());
    (fake, d, b, dir)
}

/// Waits until the daemon's keyring is locked, then checks `n1` is not served.
async fn daemon_locks(d: &crate::daemon::Daemon) {
    let locked = async {
        while d.keyring.lock().await.is_unlocked() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), locked).await.expect("the daemon locks its keyring");
    let k = d.keyring.lock().await;
    assert!(k.item("n1").is_none() && k.item_locked("n1"), "no secret is served");
}

#[tokio::test]
async fn a_worker_that_locks_after_a_panic_locks_the_daemon() {
    let (_fake, d, b, _dir) = daemon_on_the_worker().await;
    assert!(b.panic_for_test(false).await.is_err());
    daemon_locks(&d).await;
}

#[tokio::test]
async fn a_worker_that_stops_locks_the_daemon() {
    let (_fake, d, b, _dir) = daemon_on_the_worker().await;
    assert!(b.panic_for_test(true).await.is_err());
    daemon_locks(&d).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_during_an_unlock_wins() {
    let (fake, b, _dir) = handle(vec![]).await;
    b.lock().await;
    let b = Arc::new(b);
    let mut gate = Gate::hold(&fake, "GET", "/api/sync?excludeDomains=true");
    let unlocking = tokio::spawn({
        let b = b.clone();
        async move { b.unlock(PASSWORD).await }
    });
    gate.arrived().await;
    // The core's sync holds nothing the lock needs: it is done while the sync waits.
    b.lock().await;
    assert!(matches!(b.acl_trust().await, Err(BackendError::Locked)));
    gate.open();
    assert!(matches!(unlocking.await.unwrap(), Err(BackendError::Locked)), "the unlock does not bring the keys back");
    assert!(matches!(b.acl_trust().await, Err(BackendError::Locked)));
    assert!(matches!(b.refresh().await, Err(BackendError::Locked)));
    assert!(b.describe().await.contains("0 queued change(s)"));
}

// --- unlocking through the core ---------------------------------------------------------

use crate::core_ports::storage::FileStorage;
use dybw_core::crypto::KdfParams as CoreKdf;
use dybw_core::profile::{KdfSource, accept_kdf};

impl Vault {
    /// The core's device state, as the backend keeps it.
    fn storage(&self) -> FileStorage {
        FileStorage::new(&paths_in(&self.dir), "p")
    }

    fn core_file(&self, key: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.join("tool-state/core").join(key)).ok()
    }

    /// The identity origin the KDF pin is bound to.
    fn origin(&self) -> String {
        let pin: Value = serde_json::from_str(&self.core_file("kdf-pin").unwrap()).unwrap();
        pin["origin"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn unlocks_online_and_writes_the_cache() {
    let v = github().await;
    let cache: Value = serde_json::from_slice(&std::fs::read(v.dir.join("cache/sync.json")).unwrap()).unwrap();
    assert_eq!(cache["format"], 2);
    assert_eq!(cache["email"], EMAIL);
    // The KDF the unlock ran, read back from the pin.
    assert_eq!(cache["kdf"], json!({ "type": "pbkdf2", "iterations": ITERATIONS }));
    assert!(cache["revision"].is_string());
    assert_eq!(cache["sync"]["ciphers"], v.fake.with(|s| s.sync["ciphers"].clone()));
    assert_eq!(cache["sync"]["profile"]["id"], "user1");
    // The core's device state: the pin and the id of the user key (ADR 0017, 0023).
    assert!(v.core_file("kdf-pin").is_some());
    assert!(v.core_file("user-key-id").is_some_and(|id| id.len() == 22), "{:?}", v.core_file("user-key-id"));
    // 5,000 iterations are below ADR 0017's floor: the unlock goes on, and the status says so.
    let status = v.backend.describe().await;
    assert!(status.contains("below ADR 0017's floor (PBKDF2, 5000 iterations, KDF from prelogin)"), "{status}");
    assert_eq!(v.fake.count("GET", "/api/sync"), 1, "one /sync, the core's");
    // Queued writes go out at once, as before the core: the runner can write.
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1);
}

#[tokio::test]
async fn unlocks_offline_from_the_cache() {
    let v = github().await;
    v.backend.lock().await;
    v.fake.with(|s| s.down = true);
    assert!(matches!(v.backend.unlock("wrong").await, Err(BackendError::WrongPassword)));
    let snap = v.backend.unlock(PASSWORD).await.unwrap();
    assert_eq!(snap.items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["gh"]);
    assert!(v.backend.describe().await.contains("below ADR 0017's floor"));

    // The pin is checked offline too.
    v.backend.lock().await;
    accept_kdf(&v.storage(), CoreKdf::Pbkdf2 { iterations: ITERATIONS * 2 }, &v.origin()).await.unwrap();
    let err = v.backend.unlock(PASSWORD).await.unwrap_err();
    assert!(matches!(err, BackendError::KdfWeakened { .. }), "{err}");

    // A cache without the prelogin KDF cannot open a `profile.key` account.
    let cache = v.dir.join("cache/sync.json");
    let mut doc: Value = serde_json::from_slice(&std::fs::read(&cache).unwrap()).unwrap();
    doc.as_object_mut().unwrap().remove("kdf");
    std::fs::write(&cache, serde_json::to_vec(&doc).unwrap()).unwrap();
    let err = v.backend.unlock(PASSWORD).await.unwrap_err();
    assert!(matches!(&err, BackendError::Rejected(m) if m.contains("the offline copy lacks its KDF")), "{err}");
}

#[tokio::test]
async fn a_weakened_kdf_is_refused_until_accepted() {
    let v = github().await;
    let storage = v.storage();
    accept_kdf(&storage, CoreKdf::Pbkdf2 { iterations: 10_000 }, &v.origin()).await.unwrap();
    v.backend.lock().await;
    let err = v.backend.unlock(PASSWORD).await.unwrap_err();
    assert!(
        matches!(
            err,
            BackendError::KdfWeakened {
                pinned: CoreKdf::Pbkdf2 { iterations: 10_000 },
                offered: CoreKdf::Pbkdf2 { iterations: ITERATIONS },
                kdf_source: KdfSource::Prelogin,
            }
        ),
        "{err}"
    );
    assert!(err.to_string().contains("then run `bwss kdf accept`"), "{err}");
    assert!(v.backend.state.lock().await.is_none());

    // A no at the question changes nothing.
    assert!(crate::kdf_accept(&storage, &v.origin(), async |_| Ok(false)).await.is_err());
    assert!(matches!(v.backend.unlock(PASSWORD).await, Err(BackendError::KdfWeakened { .. })));

    let mut asked = String::new();
    crate::kdf_accept(&storage, &v.origin(), async |q: &str| {
        asked = q.to_owned();
        Ok(true)
    })
    .await
    .unwrap();
    assert!(asked.contains("PBKDF2, 5000 iterations") && asked.contains(&v.origin()), "{asked}");
    assert_eq!(v.backend.unlock(PASSWORD).await.unwrap().items.len(), 1);
    let none = crate::kdf_accept(&storage, &v.origin(), async |_| Ok(true)).await.unwrap_err().to_string();
    assert!(none.contains("no unlock waits"), "{none}");

    // An offer that cannot be kept still refuses the unlock.
    accept_kdf(&storage, CoreKdf::Pbkdf2 { iterations: 10_000 }, &v.origin()).await.unwrap();
    std::fs::create_dir_all(crate::fsutil::temp_path(&v.dir.join("tool-state/core/kdf-offered"))).unwrap();
    v.backend.lock().await;
    assert!(matches!(v.backend.unlock(PASSWORD).await, Err(BackendError::KdfWeakened { .. })));
    assert!(crate::kdf_accept(&storage, &v.origin(), async |_| Ok(true)).await.is_err());
}

#[tokio::test]
async fn an_unreadable_kdf_pin_is_forgotten_once_confirmed() {
    let v = github().await;
    let origin = v.origin();
    v.backend.lock().await;
    std::fs::write(v.dir.join("tool-state/core/kdf-pin"), "{").unwrap();
    let err = v.backend.unlock(PASSWORD).await.unwrap_err();
    assert!(matches!(err, BackendError::KdfPinUnreadable), "{err}");
    assert!(err.to_string().contains("`bwss kdf accept`"), "{err}");
    let mut asked = String::new();
    crate::kdf_accept(&v.storage(), &origin, async |q: &str| {
        asked = q.to_owned();
        Ok(true)
    })
    .await
    .unwrap();
    assert!(asked.contains("unreadable") && asked.contains(&origin), "{asked}");
    assert_eq!(v.backend.unlock(PASSWORD).await.unwrap().items.len(), 1);
}

/// The `cose-v2` account of dybw-core's vectors (8c4b303), as a newer
/// Vaultwarden serves it: a COSE user key, a signed security state and
/// `masterPasswordUnlock`.
fn cose_v2() -> (Value, String) {
    let account: Value = serde_json::from_str(include_str!("../../tests/fixtures/accounts/cose-v2.json")).unwrap();
    let mut profile = account["profile"].clone();
    profile["id"] = json!("user1");
    profile["key"] = account["profileKey"].clone();
    let sync = json!({
        "profile": profile, "userDecryption": account["userDecryption"], "folders": [], "ciphers": [],
    });
    (sync, account["password"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn a_cose_v2_account_unlocks() {
    use base64::Engine as _;
    let (mut sync, password) = cose_v2();
    // B4: an item under the COSE user key is read through the core.
    let account: Value = serde_json::from_str(include_str!("../../tests/fixtures/accounts/cose-v2.json")).unwrap();
    let raw = base64::engine::general_purpose::STANDARD.decode(account["userKey"].as_str().unwrap()).unwrap();
    let user = dybw_core::crypto::SymmetricKey::from_bytes(&raw).unwrap();
    let enc = |s: &str| user.encrypt_str(s, &crate::core_ports::random::OsRandom).unwrap();
    sync["ciphers"] = json!([{
        "id": "c1", "type": 1, "organizationId": null, "revisionDate": REV, "creationDate": REV, "deletedDate": null,
        "name": enc("Cose login"), "notes": null,
        "login": { "username": null, "password": enc("cose pw"), "uris": null },
        "fields": [{ "type": 0, "name": enc("bwss:id"), "value": enc("cose") }],
    }]);
    let (fake, config, creds, paths, dir) = serve(sync);
    let b = Bitwarden::new(&config, creds, &paths).unwrap();
    let snap = b.unlock(&password).await.unwrap();
    assert_eq!(
        snap.items.iter().map(|i| (i.id.as_str(), &**i.secret)).collect::<Vec<_>>(),
        [("cose", &b"cose pw"[..])]
    );
    assert_eq!(fake.count("POST", "/identity/accounts/prelogin"), 0, "source 1 needs no prelogin");
    let core = dir.path().join("tool-state/core");
    assert_eq!(std::fs::read_to_string(core.join("security-version")).unwrap(), "2");
    assert!(core.join("user-key-id").exists());
    // B5: the core writes to it; a new item is a blob (ADR 0021).
    b.put_item(&new_item("n1", "work")).await.unwrap();
    let created = fake.with(|s| s.sync["ciphers"][1].clone());
    assert!(created["data"].is_string() && created["fields"].is_null(), "{created}");
    let shown = b.state.lock().await.as_ref().unwrap().built.marked["n1"].item.clone();
    assert_eq!((shown.secret.as_slice(), shown.collection.as_str()), (&b"tok"[..], "work"));
    b.create_collection("Home").await.unwrap();
    b.refresh().await.unwrap();
    let collections = b.state.lock().await.as_ref().unwrap().built.snapshot.collections.clone();
    assert!(collections.iter().any(|c| c.id == "home"), "{collections:?}");
    b.delete_item(&shown).await.unwrap();
    assert!(fake.cipher(created["id"].as_str().unwrap())["deletedDate"].is_string());
    assert!(!b.describe().await.contains("COSE"));

    // ADR 0019: a version below the one this device saw stops the unlock until accepted.
    b.lock().await;
    std::fs::write(core.join("security-version"), "3").unwrap();
    let err = b.unlock(&password).await.unwrap_err();
    assert!(matches!(err, BackendError::SecurityDowngrade { seen: 3, offered: 2 }), "{err}");
    assert!(err.to_string().contains("`bwss security accept 2`"), "{err}");
    let storage = FileStorage::new(&paths, "p");
    assert!(crate::security_accept(&storage, 2, async |_| Ok(false)).await.is_err());
    let mut asked = String::new();
    crate::security_accept(&storage, 2, async |q: &str| {
        asked = q.to_owned();
        Ok(true)
    })
    .await
    .unwrap();
    assert!(asked.contains("version 2"), "{asked}");
    b.unlock(&password).await.unwrap();

    // Offline, from the cache, with the same checks.
    b.lock().await;
    fake.with(|s| s.down = true);
    b.unlock(&password).await.unwrap();
}

#[tokio::test]
async fn a_new_user_key_resets_queue_and_acl_confirmations() {
    let v = github().await;
    let old = v.core_file("user-key-id").unwrap();
    // A change queued offline, and an ACL line confirmed on this device.
    v.fake.with(|s| s.down = true);
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    v.fake.with(|s| s.down = false);
    assert_eq!(v.queue_file(), 1);
    let confirmed = v.dir.join("tool-state/acl-confirmed");
    std::fs::write(&confirmed, "{}").unwrap();
    v.backend.lock().await;

    // The user key is rotated in the web vault.
    let rotated = SymmetricKey::generate(&OsRandom).unwrap();
    v.fake.with(|s| s.sync["profile"]["key"] = json!(protect(&rotated)));
    v.backend.unlock(PASSWORD).await.unwrap();
    let new = v.core_file("user-key-id").unwrap();
    assert_ne!(new, old);
    assert!(v.dir.join(format!("state/queue.{old}.bak")).exists(), "set aside, never opened with the new key");
    assert!(!v.dir.join("state/queue.json").exists());
    assert!(!confirmed.exists(), "every ACL line is asked again");
    assert_eq!(v.queued().await, 0);
    let status = v.backend.describe().await;
    assert!(status.contains(&format!("queue.{old}.bak")) && status.contains("asked again"), "{status}");
    assert!(status.contains("1 change queued before that cannot be sent"), "counted without opening it: {status}");

    // Unchanged on the next unlock: nothing more is reset.
    v.backend.lock().await;
    std::fs::write(&confirmed, "{}").unwrap();
    v.backend.unlock(PASSWORD).await.unwrap();
    assert!(confirmed.exists());
    assert!(!v.backend.describe().await.contains("asked again"));

    // The same old key changing away again keeps both backups.
    v.backend.lock().await;
    std::fs::write(v.dir.join("tool-state/core/user-key-id"), &old).unwrap();
    std::fs::write(v.dir.join("state/queue.json"), "{}").unwrap();
    v.backend.unlock(PASSWORD).await.unwrap();
    let second = v.dir.join(format!("state/queue.{old}.bak.2"));
    assert_eq!(std::fs::read(&second).unwrap(), b"{}");
    assert!(std::fs::metadata(v.dir.join(format!("state/queue.{old}.bak"))).unwrap().len() > 2, "the first one kept");
    assert!(v.backend.describe().await.contains(&second.display().to_string()), "the name used is reported");

    // A planted id never names a path outside the state directory.
    v.backend.lock().await;
    std::fs::write(v.dir.join("tool-state/core/user-key-id"), "../../x/evil").unwrap();
    std::fs::write(v.dir.join("state/queue.json"), "{}").unwrap();
    v.backend.unlock(PASSWORD).await.unwrap();
    assert!(v.dir.join("state/queue.xevil.bak").exists());
}

#[tokio::test]
async fn a_key_change_that_cannot_reset_says_so() {
    let v = github().await;
    v.backend.lock().await;
    let core = v.dir.join("tool-state/core");
    // An id too long for a file name: the queue cannot be moved under it.
    let long = "o".repeat(250);
    std::fs::write(core.join("user-key-id"), &long).unwrap();
    std::fs::create_dir_all(v.dir.join("state")).unwrap();
    std::fs::write(v.dir.join("state/queue.json"), "{}").unwrap();
    std::fs::create_dir_all(v.dir.join("tool-state/acl-confirmed/full")).unwrap();
    std::fs::create_dir_all(crate::fsutil::temp_path(&core.join("user-key-id"))).unwrap();
    v.backend.unlock(PASSWORD).await.unwrap();
    let status = v.backend.describe().await;
    assert!(status.contains("the write queue could not be set aside"), "{status}");
    assert!(status.contains("the ACL confirmations could not be reset"), "{status}");
    assert_eq!(std::fs::read_to_string(core.join("user-key-id")).unwrap(), long, "not recorded: asked again next time");
}

#[tokio::test]
async fn a_write_racing_a_cose_unlock_waits_for_it_and_is_sent() {
    use std::rc::Rc;
    use std::time::Duration;
    let (sync, password) = cose_v2();
    let (fake, config, creds, paths, dir) = serve(sync);
    let b = Rc::new(Bitwarden::new(&config, creds, &paths).unwrap());
    let opened = dir.path().join("tool-state/core/user-key-id");
    tokio::task::LocalSet::new()
        .run_until(async move {
            let held = b.queue.lock().await;
            let unlocking = tokio::task::spawn_local({
                let b = b.clone();
                async move { b.unlock(&password).await }
            });
            // The key is open: next the unlock waits for the queue.
            while !opened.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            // Sent while the keyring is still locked, it waits behind the unlock.
            let writing = tokio::task::spawn_local({
                let b = b.clone();
                async move { b.put_item(&new_item("n1", "login")).await }
            });
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(held);
            unlocking.await.unwrap().unwrap();
            writing.await.unwrap().unwrap();
            assert_eq!(fake.count("POST", "/api/ciphers"), 1, "sent under the account's own key");
            assert!(fake.with(|s| s.sync["ciphers"][0]["data"].is_string()), "as a blob");
            assert_eq!(b.queue.lock().await.len(), 0, "nothing queued");
        })
        .await;
}

/// A personal blob cipher (ADR 0021) under `k`: a login whose whole item is
/// sealed in `data`, marked with `fields`.
fn blob(k: &SymmetricKey, cid: &str, fields: &[(&str, &str)], password: &str) -> Value {
    use base64::Engine as _;
    use dybw_core::crypto::{Cbor, EnvelopeNamespace, SymmetricKey as CoreKey, seal_envelope};
    let rng = crate::core_ports::random::OsRandom;
    let t = Cbor::text;
    let fields = fields.iter().map(|(n, v)| Cbor::Map(vec![(t("name"), t(n)), (t("value"), t(v))])).collect();
    let content = Cbor::Map(vec![
        (t("name"), t("Blob")),
        (t("notes"), Cbor::Null),
        (
            t("typeData"),
            Cbor::Map(vec![(t("type"), t("login")), (t("username"), t("me")), (t("password"), t(password))]),
        ),
        (t("fields"), Cbor::Array(fields)),
    ]);
    let sealed = Cbor::Map(vec![(t("version"), t("1")), (t("content"), content)]);
    let user = CoreKey::from_bytes(&k.to_bytes()).unwrap();
    let item = CoreKey::generate(&rng).unwrap();
    let (envelope, cek) = seal_envelope(&sealed, EnvelopeNamespace::VaultItem, &rng).unwrap();
    let data = json!({
        "format_version": 1,
        "wrapped_cek": item.encrypt(&CoreKey::Cose(cek).to_bytes(), &rng).unwrap(),
        "envelope": base64::engine::general_purpose::STANDARD.encode(envelope),
    });
    json!({
        "id": cid, "type": 1, "organizationId": null, "folderId": null, "revisionDate": REV, "creationDate": REV,
        "deletedDate": null, "name": null, "notes": null, "login": null, "fields": null, "passwordHistory": null,
        "key": user.encrypt(&item.to_bytes(), &rng).unwrap(), "data": data.to_string(),
    })
}

#[tokio::test]
async fn blob_items_are_served() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let marked = blob(&k, "c1", &[("bwss:id", "b"), ("bwss:attr:service", "blobby")], "sealed pw");
    let unmarked = blob(&k, "c2", &[("other", "x")], "never read");
    let v = vault_with(vec![marked, unmarked], k, true).await;
    let item = v.item("b").await;
    assert_eq!(&*item.secret, b"sealed pw");
    assert_eq!(item.attributes["service"], "blobby");
    assert_eq!(item.attributes["bwss:name"], "Blob", "the name comes from inside the blob");
    let snap = v.snapshot().await;
    assert_eq!(snap.items.len(), 1);
    assert!(snap.held.is_empty(), "{:?}", snap.held);
    assert!(!v.backend.describe().await.contains("newer encryption format"));
}

#[tokio::test]
async fn a_held_item_keeps_its_last_value() {
    let v = github().await;
    assert_eq!(&*v.item("gh").await.secret, b"pw");
    // Another client gives it a value source this bwss cannot read: skipped,
    // and the id it holds keeps serving what was read last.
    let k = core_key(&v.keys.user);
    v.edit_elsewhere("c1", |c| {
        c["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "type": 0, "name": k.encrypt_str("bwss:location", &OsRandom).unwrap(),
            "value": k.encrypt_str("somewhere-new", &OsRandom).unwrap() }));
        c["login"]["password"] = json!(k.encrypt_str("changed", &OsRandom).unwrap());
    });
    let snap = v.snapshot().await;
    assert_eq!(snap.items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["gh"], "never deleted while held");
    assert_eq!(&*v.item("gh").await.secret, b"pw", "the last good value");
    assert!(v.backend.describe().await.contains("skipped: c1: unknown bwss:location"));
    // The binding stays on the held cipher.
    assert_eq!(snap.ciphers["gh"], "c1");
}

#[tokio::test]
async fn a_newer_format_item_is_not_served_and_is_listed() {
    let v = github().await;
    let k = core_key(&v.keys.user);
    v.edit_elsewhere("c1", |c| {
        c["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "type": 0, "name": k.encrypt_str("dybw:requires", &OsRandom).unwrap(),
            "value": k.encrypt_str("bwss:future\nother:thing", &OsRandom).unwrap() }));
    });
    let snap = v.snapshot().await;
    assert!(snap.items.is_empty(), "ADR 0020: not served, not even as last read");
    assert_eq!(snap.held.iter().collect::<Vec<_>>(), ["c1"], "not deleted: the locked index keeps it");
    let status = v.backend.describe().await;
    assert!(status.contains("skipped: c1: it needs what this bwss does not implement (bwss:future)"), "{status}");
    // After a restart it is still not served.
    v.backend.lock().await;
    assert!(v.backend.unlock(PASSWORD).await.unwrap().items.is_empty());
}

#[tokio::test]
async fn label_falls_back_to_the_id() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let mut labelled = hand_marked(&k, "c2", "lab");
    labelled["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "type": 0, "name": k.encrypt_str("bwss:label", &OsRandom).unwrap(),
        "value": k.encrypt_str("My label", &OsRandom).unwrap() }));
    let v = vault(vec![hand_marked(&k, "c1", "gh"), labelled], k).await;
    // ADR 0015: the item name ("GitHub") is no label.
    assert_eq!(v.item("gh").await.label, "gh");
    assert_eq!(v.item("lab").await.label, "My label");
}

#[tokio::test]
async fn derived_attributes_are_off_by_default() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
    let item = v.item("gh").await;
    assert_eq!(item.attributes["bwss:id"], "gh", "the id is always shown");
    for a in ["bwss:name", "bwss:username", "bwss:uri"] {
        assert!(!item.attributes.contains_key(a), "{a}");
    }
    assert_eq!(item.attributes["service"], "git");
    assert_eq!(item.label, "gh");
}

#[tokio::test]
async fn status_announces_a_carried_over_derive_flag() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
    assert!(!v.backend.describe().await.contains("carried over"));
    let paths = paths_in(&v.dir);
    std::fs::create_dir_all(&paths.tool_state).unwrap();
    std::fs::write(paths.derive_carried(), "on\n").unwrap();
    let status = v.backend.describe().await;
    assert!(status.contains("visible on the session bus") && status.contains("`bwss derive off`"), "{status}");
    crate::config::set_derive(&paths, false).unwrap();
    assert!(!v.backend.describe().await.contains("carried over"), "an explicit choice ends it");
}

#[tokio::test]
async fn derive_on_shows_them_and_off_hides_them_at_once() {
    // The terminal confirmation is `main::derive` (see `turning_derived_attributes_on_says_what_becomes_visible`
    // and the e2e tests); this is what the device flag does.
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault_with(vec![hand_marked(&k, "c1", "gh")], k, true).await;
    let item = v.item("gh").await;
    assert_eq!(item.attributes["bwss:name"], "GitHub");
    assert_eq!(item.attributes["bwss:username"], "me");
    assert_eq!(item.attributes["bwss:uri"], "https://github.com");
    assert_eq!(item.label, "GitHub", "ADR 0015: the item name is the label while derived attributes are on");

    // Turned off again: the next refresh drops them, though the server did not change.
    std::fs::remove_file(v.dir.join("tool-state").join("derive-on")).unwrap();
    let snap = v.backend.refresh().await.unwrap().expect("the snapshot changed");
    assert!(!snap.items[0].attributes.contains_key("bwss:name"));
    assert!(!v.item("gh").await.attributes.contains_key("bwss:name"));
}

/// The fake's copy of `cid` replaced by `cipher` as it was, as a server
/// restored from a backup sends it.
fn roll_back(v: &Vault, cid: &str, cipher: Value) {
    v.fake.with(|s| {
        s.rev += 1;
        *s.find(cid).unwrap() = cipher;
    });
}

#[tokio::test]
async fn a_rolled_back_item_keeps_its_cached_value() {
    let v = github().await;
    let old = v.fake.cipher("c1");
    let k = core_key(&v.keys.user);
    v.edit_elsewhere("c1", |c| c["login"]["password"] = json!(k.encrypt_str("new", &OsRandom).unwrap()));
    assert_eq!(&*v.item("gh").await.secret, b"new");

    roll_back(&v, "c1", old);
    assert_eq!(&*v.item("gh").await.secret, b"new", "ADR 0019: never below the cached base");
    let status = v.backend.describe().await;
    assert!(status.contains("older on the server than the copy this device has, which is kept: gh"), "{status}");
    assert!(status.contains("`bwss sync --accept-rollback`"), "{status}");

    // A restart compares with the offline copy.
    v.backend.lock().await;
    let snap = v.backend.unlock(PASSWORD).await.unwrap();
    assert_eq!(&*snap.items[0].secret, b"new");
    assert!(v.backend.describe().await.contains("which is kept: gh"));
}

impl Vault {
    /// What `bwss sync --accept-rollback` does with the keyring unlocked.
    async fn accept_rollbacks(&self) -> Vec<String> {
        crate::accept_rollbacks(true, &FileStorage::new(&paths_in(&self.dir), "p")).await.unwrap()
    }

    /// `gh`'s server copy taken back to `old` after a newer one was synced.
    async fn rolled_back(&self, cid: &str, password: &str) {
        let old = self.fake.cipher(cid);
        let k = core_key(&self.keys.user);
        self.edit_elsewhere(cid, |c| c["login"]["password"] = json!(k.encrypt_str(password, &OsRandom).unwrap()));
        self.snapshot().await;
        roll_back(self, cid, old);
        self.snapshot().await;
    }
}

#[tokio::test]
async fn a_write_to_a_rolled_back_item_waits_until_the_rollback_is_settled() {
    let v = github().await;
    v.rolled_back("c1", "new").await;
    let puts = v.fake.count("PUT", "/api/ciphers/c1");
    let item = ItemData { label: "Mine".into(), ..v.item_offline("gh").await };
    // Never sent over the server's older copy: kept queued, and listed.
    v.backend.put_item(&item).await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1));
    assert_eq!(v.fake.count("PUT", "/api/ciphers/c1"), puts, "nothing was sent");
    assert_eq!(v.item_offline("gh").await.label, "Mine", "the change is shown");
    let status = v.backend.describe().await;
    assert!(
        status.contains("queued changes wait while the server holds an older copy than this device: gh"),
        "{status}"
    );

    // Accepted: the change goes to the server's version.
    v.accept_rollbacks().await;
    v.backend.refresh().await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert_eq!(v.marked("c1").item.label, "Mine");
    assert_eq!(&*v.marked("c1").item.secret, b"pw", "on the server's version");
}

#[tokio::test]
async fn accept_rollback_takes_the_server_version() {
    let v = github().await;
    v.rolled_back("c1", "new").await;
    assert_eq!(&*v.item_offline("gh").await.secret, b"new");
    let accepted = v.dir.join("tool-state/core/accept-rollback");
    let shown = v.accept_rollbacks().await;
    assert!(shown.len() == 1 && shown[0].starts_with("accepting the server's version of gh (cipher c1, "), "{shown:?}");
    // Taken even when the account did not change since: it always pulls.
    assert_eq!(&*v.item("gh").await.secret, b"pw");
    assert!(!accepted.exists(), "for one sync only");
    assert!(!v.backend.describe().await.contains("which is kept"));
    assert!(!v.dir.join("tool-state/core/rollbacks-held").exists(), "nothing is held back now");

    // The server's version is the base now: nothing to report next time.
    assert_eq!(&*v.item("gh").await.secret, b"pw");
    v.backend.lock().await;
    v.backend.unlock(PASSWORD).await.unwrap();
    assert!(!v.backend.describe().await.contains("which is kept"));

    // An accept the keyring locked before using is dropped, never applied later.
    v.rolled_back("c1", "newer").await;
    v.accept_rollbacks().await;
    v.backend.lock().await;
    assert!(!accepted.exists(), "dropped at lock");
    assert_eq!(&*v.backend.unlock(PASSWORD).await.unwrap().items[0].secret, b"newer");
    // And one left behind (a crash) is never applied by an unlock.
    v.accept_rollbacks().await;
    v.backend.lock().await;
    std::fs::write(&accepted, std::fs::read(v.dir.join("tool-state/core/rollbacks-held")).unwrap()).unwrap();
    assert_eq!(&*v.backend.unlock(PASSWORD).await.unwrap().items[0].secret, b"newer");
    assert!(!accepted.exists());
}

#[tokio::test]
async fn accept_rollback_takes_only_the_listed_versions() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let v = vault(vec![hand_marked(&k, "c1", "gh"), hand_marked(&k, "c2", "tw")], core_key(&k)).await;
    let (gh_old, tw_old) = (v.fake.cipher("c1"), v.fake.cipher("c2"));
    v.edit_elsewhere("c1", |c| c["login"]["password"] = json!(k.encrypt_str("gh-new", &OsRandom).unwrap()));
    v.edit_elsewhere("c2", |c| c["login"]["password"] = json!(k.encrypt_str("tw-new", &OsRandom).unwrap()));
    v.snapshot().await;
    roll_back(&v, "c1", gh_old.clone());
    v.snapshot().await;
    assert!(v.backend.describe().await.contains("which is kept: gh;"));
    assert_eq!(v.accept_rollbacks().await.len(), 1);

    // After the accept, before its sync: tw goes back too, and gh further back
    // than the version the user saw.
    roll_back(&v, "c2", tw_old);
    let mut gh_older = gh_old;
    gh_older["revisionDate"] = json!("2025-06-01T00:00:00Z");
    roll_back(&v, "c1", gh_older);
    let snap = v.snapshot().await;
    let secret = |id: &str| snap.items.iter().find(|i| i.id == id).unwrap().secret.clone();
    assert_eq!(&*secret("gh"), b"gh-new", "a version other than the listed one stays held");
    assert_eq!(&*secret("tw"), b"tw-new", "a rollback the user did not see stays held");
    let status = v.backend.describe().await;
    assert!(status.contains("which is kept: gh, tw"), "{status}");
    assert!(!v.dir.join("tool-state/core/accept-rollback").exists(), "used by that one sync");
}

#[tokio::test]
async fn a_bound_winner_stays_after_a_restart() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let (fake, config, creds, paths, dir) = server(vec![hand_marked(&k, "c1", "gh")], &k);
    let b = Bitwarden::new(&config, creds.clone(), &paths).unwrap();
    b.unlock(PASSWORD).await.unwrap();
    let bindings = dir.path().join("tool-state/core/bindings");
    let sealed = std::fs::read_to_string(&bindings).unwrap();
    // An EncString holds no quote; the JSON map inside would.
    assert!(sealed.starts_with("2.") && !sealed.contains('"'), "sealed, never plain: {sealed}");
    b.lock().await;
    drop(b);

    // A clone with an older creation date: §7 alone would pick it.
    let mut clone = hand_marked(&k, "c0", "gh");
    clone["creationDate"] = json!("2020-01-01T00:00:00Z");
    clone["login"]["password"] = json!(k.encrypt_str("clone", &OsRandom).unwrap());
    fake.with(|s| s.sync["ciphers"].as_array_mut().unwrap().push(clone));

    let b = Bitwarden::new(&config, creds.clone(), &paths).unwrap();
    let snap = b.unlock(PASSWORD).await.unwrap();
    assert_eq!(&*snap.items[0].secret, b"pw", "ADR 0019: the bound cipher keeps its id");
    assert_eq!(snap.ciphers["gh"], "c1");
    assert!(b.describe().await.contains("duplicate id gh: 1 items ignored"));
    b.lock().await;

    // Without the bindings, they are read again from the offline copy, which
    // already holds both: §7 decides, and the status says protection is reduced.
    std::fs::remove_file(&bindings).unwrap();
    let b = Bitwarden::new(&config, creds, &paths).unwrap();
    assert_eq!(&*b.unlock(PASSWORD).await.unwrap().items[0].secret, b"clone");
    let status = b.describe().await;
    assert!(status.contains("the saved item bindings are missing: duplicate and rollback protection"), "{status}");
    // Bindings that do not open are read again the same way.
    b.lock().await;
    std::fs::write(&bindings, "2.garbage").unwrap();
    assert_eq!(&*b.unlock(PASSWORD).await.unwrap().items[0].secret, b"clone");
    assert!(b.describe().await.contains("the saved item bindings cannot be read ("));
    // A new device (no offline copy either) has nothing to report.
    b.lock().await;
    std::fs::remove_file(&bindings).unwrap();
    std::fs::remove_file(dir.path().join("cache/sync.json")).unwrap();
    b.unlock(PASSWORD).await.unwrap();
    assert!(!b.describe().await.contains("bindings"));
}

#[tokio::test]
async fn lost_bindings_do_not_switch_rollback_detection_off() {
    let v = github().await;
    let old = v.fake.cipher("c1");
    let k = core_key(&v.keys.user);
    v.edit_elsewhere("c1", |c| c["login"]["password"] = json!(k.encrypt_str("new", &OsRandom).unwrap()));
    v.snapshot().await;
    v.backend.lock().await;
    std::fs::remove_file(v.dir.join("tool-state/core/bindings")).unwrap();
    roll_back(&v, "c1", old);
    let snap = v.backend.unlock(PASSWORD).await.unwrap();
    assert_eq!(&*snap.items[0].secret, b"new", "the offline copy still says what gh was");
    let status = v.backend.describe().await;
    assert!(status.contains("which is kept: gh") && status.contains("bindings are missing"), "{status}");
}

#[tokio::test]
async fn bindings_that_cannot_be_read_or_kept_do_not_stop_the_unlock() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let (fake, config, creds, paths, dir) = server(vec![hand_marked(&k, "c1", "gh")], &k);
    // A directory where the file should be: reading and replacing it fail.
    let bindings = dir.path().join("tool-state/core/bindings");
    std::fs::create_dir_all(&bindings).unwrap();
    let b = Bitwarden::new(&config, creds, &paths).unwrap();
    assert_eq!(b.unlock(PASSWORD).await.unwrap().items.len(), 1);
    assert!(b.describe().await.contains("the saved item bindings cannot be read ("));
    // A new item changes the bindings: they cannot be written, and the sync goes on.
    fake.with(|s| {
        s.rev += 1;
        s.sync["ciphers"].as_array_mut().unwrap().push(hand_marked(&k, "c2", "tw"));
    });
    assert_eq!(b.refresh().await.unwrap().unwrap().items.len(), 2);
    assert!(bindings.is_dir(), "left as it was");
}

#[tokio::test]
async fn an_accepted_rollback_that_cannot_be_cleared_is_still_taken() {
    use std::os::unix::fs::PermissionsExt as _;
    let v = github().await;
    let old = v.fake.cipher("c1");
    let k = core_key(&v.keys.user);
    v.edit_elsewhere("c1", |c| c["login"]["password"] = json!(k.encrypt_str("new", &OsRandom).unwrap()));
    v.snapshot().await;
    roll_back(&v, "c1", old);
    v.snapshot().await;
    v.accept_rollbacks().await;
    let core = v.dir.join("tool-state/core");
    // The record cannot be removed (for a user other than root).
    std::fs::set_permissions(&core, std::fs::Permissions::from_mode(0o500)).unwrap();
    let secret = v.item("gh").await.secret;
    let status = v.backend.describe().await;
    let stuck = core.join("accept-rollback").exists();
    // Never applied twice, even to the same versions coming back.
    v.rolled_back("c1", "later").await;
    let later = v.item("gh").await.secret;
    std::fs::set_permissions(&core, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(&*secret, b"pw");
    if stuck {
        assert!(status.contains("the accepted rollbacks could not be cleared"), "{status}");
        assert_eq!(&*later, b"later");
    }
}

#[tokio::test]
async fn a_migrated_queue_keeps_its_old_file_until_a_flush_moves_on() {
    let v = github().await;
    v.backend.lock().await;
    // A delete queued by bwss's format-3 writer.
    let plain = format!(r#"[{{"Delete":{{"id":"gh","base_revision":"{REV}","cipher_id":"c1"}}}}]"#);
    let key = super::bitwarden::queue_key(&v.keys.user);
    let old = json!({ "format": 3, "ops": key.encrypt(plain.as_bytes(), &OsRandom).unwrap() });
    std::fs::write(v.dir.join("state/queue.json"), serde_json::to_vec(&old).unwrap()).unwrap();
    let backup = v.dir.join("state/queue.json.v3.bak");

    // Offline: migrated, nothing sent, the old file kept.
    v.fake.with(|s| s.down = true);
    v.backend.unlock(PASSWORD).await.unwrap();
    assert_eq!((v.queued().await, v.queue_file()), (1, 1));
    assert_eq!(serde_json::from_slice::<Value>(&std::fs::read(&backup).unwrap()).unwrap(), old);
    assert!(v.backend.refresh().await.is_err());
    assert!(backup.exists(), "a flush that sends nothing keeps it");

    // The delete is sent: the old file would replay it, so it goes.
    v.fake.with(|s| s.down = false);
    v.backend.refresh().await.unwrap();
    assert_eq!((v.queued().await, v.queue_file()), (0, 0));
    assert!(!backup.exists());

    // One that cannot be removed is left; the flush goes on.
    std::fs::create_dir_all(backup.join("x")).unwrap();
    v.fake.with(|s| s.down = true);
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    v.fake.with(|s| s.down = false);
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queued().await, 0);
    assert!(backup.is_dir());
}

#[tokio::test]
async fn bindings_have_a_key_of_their_own() {
    let k = SymmetricKey::generate(&OsRandom).unwrap();
    let (_fake, config, creds, paths, dir) = server(vec![hand_marked(&k, "c1", "gh")], &k);
    let user = core_key(&k);
    let b = Bitwarden::new(&config, creds.clone(), &paths).unwrap();
    b.unlock(PASSWORD).await.unwrap();
    let bindings = dir.path().join("tool-state/core/bindings");
    let open = |key: &dybw_core::crypto::SymmetricKey| {
        let sealed = std::fs::read_to_string(&bindings).unwrap();
        key.decrypt(sealed.trim()).ok().and_then(|j| serde_json::from_slice::<BTreeMap<String, String>>(&j).ok())
    };
    let bound = open(&user.derive_bwss("bindings")).expect("sealed with the bindings key");
    assert_eq!(bound["gh"], "c1");
    assert!(open(&super::bitwarden::queue_key(&user)).is_none(), "never with the queue key");
    b.lock().await;

    // Bindings an older bwss sealed with the queue key are read once and sealed again.
    let json = serde_json::to_vec(&bound).unwrap();
    std::fs::write(&bindings, super::bitwarden::queue_key(&user).encrypt(&json, &OsRandom).unwrap()).unwrap();
    b.unlock(PASSWORD).await.unwrap();
    assert!(!b.describe().await.contains("bindings"));
    assert_eq!(open(&user.derive_bwss("bindings")), Some(bound));
    b.lock().await;

    // Another file of the queue key never passes for bindings.
    let queue =
        super::ops::seal(&Queue::default(), &BTreeMap::new(), &super::bitwarden::queue_key(&user), "u", &OsRandom);
    let records = super::bitwarden::queue_key(&user).encrypt(b"{}", &OsRandom).unwrap();
    for planted in [queue.unwrap()["set"].as_str().unwrap().to_owned(), records] {
        std::fs::write(&bindings, planted).unwrap();
        b.unlock(PASSWORD).await.unwrap();
        assert!(b.describe().await.contains("the saved item bindings cannot be read ("));
        b.lock().await;
    }
}

#[tokio::test]
async fn the_hub_stops_on_lock() {
    use crate::core_ports::events::test_hub::{Seen, serve as serve_hub};
    let user = SymmetricKey::generate(&OsRandom).unwrap();
    let (_fake, config, creds, paths, _dir) = server(vec![], &user);
    let (hub, mut seen) = serve_hub(1, std::time::Duration::ZERO).await;
    let mut b = Bitwarden::new(&config, creds, &paths).unwrap();
    b.urls.notifications = hub;
    let vault = std::rc::Rc::new(b);
    let mut changes = vault.changes.subscribe();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            vault.unlock_and_follow(PASSWORD).await.unwrap();
            let Some(Seen::Open(uri)) = seen.recv().await else { panic!("the hub never connected") };
            assert!(uri.starts_with("/hub?access_token=") && uri.len() > "/hub?access_token=".len(), "{uri}");
            // Started again (a second unlock): the first connection goes, one stays.
            vault.start_hub(vault.lock_generation.load(std::sync::atomic::Ordering::SeqCst));
            let two = [seen.recv().await.unwrap(), seen.recv().await.unwrap()];
            assert!(two.contains(&Seen::Closed) && two.iter().any(|s| matches!(s, Seen::Open(_))), "{two:?}");
            // The change the hub announced reaches the daemon's side.
            tokio::time::timeout(std::time::Duration::from_secs(5), changes.changed()).await.unwrap().unwrap();
            vault.lock().await;
            assert!(vault.hub.lock().unwrap().is_none());
            assert_eq!(seen.recv().await, Some(Seen::Closed));
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            assert!(seen.try_recv().is_err(), "no reconnect after the lock");
            // A hub for an unlock that a lock overtook is refused.
            vault.start_hub(0);
            assert!(vault.hub.lock().unwrap().is_none());
        })
        .await;
}

/// Holds `vault.state` from when it gets it until the sender is used or dropped.
fn hold_state(vault: &std::rc::Rc<Bitwarden>) -> tokio::sync::oneshot::Sender<()> {
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let v = vault.clone();
    tokio::task::spawn_local(async move {
        let _guard = v.state.lock().await;
        let _ = released.await;
    });
    release
}

async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

/// An unlock whose last step waits on the state while a lock begins: the
/// unlock succeeds, then the lock clears the keys. Its hub must not start,
/// nor outlive the lock.
#[tokio::test]
async fn a_lock_during_an_unlock_leaves_no_hub() {
    use crate::core_ports::events::test_hub::serve as serve_hub;
    let user = SymmetricKey::generate(&OsRandom).unwrap();
    let (_fake, config, creds, paths, _dir) = server(vec![], &user);
    let (hub, mut seen) = serve_hub(0, std::time::Duration::ZERO).await;
    let mut b = Bitwarden::new(&config, creds, &paths).unwrap();
    b.urls.notifications = hub;
    let vault = std::rc::Rc::new(b);
    tokio::task::LocalSet::new()
        .run_until(async {
            // The unlock stops while installing its keys (it holds the state, waits on the client).
            let client = vault.client.lock().await;
            let v = vault.clone();
            let unlocking = tokio::task::spawn_local(async move { v.unlock_and_follow(PASSWORD).await });
            while vault.state.try_lock().is_ok() {
                tokio::task::yield_now().await;
            }
            // Holders of the state in turn, so the unlock's last step queues before the lock.
            let first = hold_state(&vault);
            settle().await;
            drop(client); // the unlock installs, then waits on `first` (its queue check)
            settle().await;
            let second = hold_state(&vault);
            settle().await;
            let _ = first.send(()); // the queue check passes; the last step waits on `second`
            settle().await;
            let v = vault.clone();
            let locking = tokio::task::spawn_local(async move { v.lock().await });
            settle().await; // the lock found no hub, and waits behind the unlock
            let _ = second.send(());
            assert!(unlocking.await.unwrap().is_ok(), "the unlock won the state");
            locking.await.unwrap();
            assert!(vault.hub.lock().unwrap().is_none(), "no hub after the lock");
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            assert!(seen.try_recv().is_err(), "no connection after the lock");
        })
        .await;
}

#[tokio::test]
async fn notifications_off_starts_no_hub() {
    let user = SymmetricKey::generate(&OsRandom).unwrap();
    let (_fake, mut config, creds, paths, _dir) = server(vec![], &user);
    config.notifications = false;
    let vault = std::rc::Rc::new(Bitwarden::new(&config, creds, &paths).unwrap());
    tokio::task::LocalSet::new()
        .run_until(async {
            vault.unlock_and_follow(PASSWORD).await.unwrap();
            assert!(vault.hub.lock().unwrap().is_none());
        })
        .await;
}

#[tokio::test]
async fn a_hub_whose_unlock_is_over_ends_by_itself() {
    let user = SymmetricKey::generate(&OsRandom).unwrap();
    let (_fake, config, creds, paths, _dir) = server(vec![], &user);
    let vault = Bitwarden::new(&config, creds, &paths).unwrap();
    let generation = vault.lock_generation.load(std::sync::atomic::Ordering::SeqCst);
    vault.lock().await;
    // Not left to the abort alone: it returns before it connects.
    tokio::time::timeout(std::time::Duration::from_secs(5), vault.follow_hub(generation)).await.unwrap();
}

#[tokio::test]
async fn a_panic_while_locking_after_a_panic_stops_the_worker() {
    let (_fake, b, _dir) = handle(vec![]).await;
    assert!(b.acl_trust().await.is_ok(), "unlocked");
    assert!(matches!(b.panic_for_test(true).await, Err(BackendError::Unavailable(m)) if m == STOPPED));
    // The keys may still be held: the worker stops instead of serving them.
    let stopped = async {
        while b.describe().await != STOPPED {
            tokio::task::yield_now().await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), stopped).await.expect("the worker stops");
    assert!(matches!(b.acl_trust().await, Err(BackendError::Unavailable(m)) if m == STOPPED));
    assert!(matches!(b.unlock(PASSWORD).await, Err(BackendError::Unavailable(m)) if m == STOPPED));
}

/// The record is turned into a directory while the sync that uses it runs:
/// it cannot be removed, by root either.
#[tokio::test]
async fn an_accept_record_that_cannot_be_removed_is_used_once_and_reported() {
    let v = github().await;
    v.rolled_back("c1", "new").await;
    v.accept_rollbacks().await;
    let accepted = v.dir.join("tool-state/core/accept-rollback");
    let mut gate = Gate::hold(&v.fake, "GET", "/api/sync?excludeDomains=true");
    let backend = v.backend.clone();
    let local = tokio::task::LocalSet::new();
    let running = local.spawn_local(async move { backend.refresh().await });
    local.run_until(gate.arrived()).await;
    std::fs::remove_file(&accepted).unwrap();
    std::fs::create_dir_all(accepted.join("stuck")).unwrap();
    gate.open();
    local.run_until(running).await.unwrap().unwrap();
    assert_eq!(&*v.item("gh").await.secret, b"pw", "the server's version was taken");
    let status = v.backend.describe().await;
    assert!(status.contains("the accepted rollbacks could not be cleared"), "{status}");
    // Spent: the next sync, with a rollback again, holds it back.
    v.rolled_back("c1", "again").await;
    v.backend.refresh().await.unwrap();
    assert_eq!(&*v.item("gh").await.secret, b"again");
    assert!(accepted.is_dir());
}

#[tokio::test]
async fn a_held_rollback_list_that_cannot_be_kept_does_not_stop_a_sync() {
    let v = github().await;
    let held = v.dir.join("tool-state/core/rollbacks-held");
    std::fs::create_dir_all(held.join("stuck")).unwrap();
    let k = core_key(&v.keys.user);
    v.edit_elsewhere("c1", |c| c["login"]["password"] = json!(k.encrypt_str("new", &OsRandom).unwrap()));
    v.backend.refresh().await.unwrap();
    assert_eq!(&*v.item("gh").await.secret, b"new");
    assert!(held.is_dir());
}

#[tokio::test]
async fn a_cache_without_a_cipher_list_records_no_server_answer() {
    let v = github().await;
    let queue = v.backend.queue.lock().await;
    let mut guard = v.backend.state.lock().await;
    let state = guard.as_mut().unwrap();
    state.sync.as_object_mut().unwrap().remove("ciphers");
    v.backend.absorb(state, &queue, Effect::Trashed("c1".into()));
    assert!(state.sync.get("ciphers").is_none(), "no list is made up");
    assert!(state.built.snapshot.items.is_empty());
}

#[tokio::test]
async fn a_queued_new_registry_note_the_server_refuses_is_dropped() {
    let v = github().await;
    v.fake.with(|s| s.down = true);
    v.backend.create_collection("Work").await.unwrap();
    v.fake.with(|s| s.down = false);
    v.fake.fault("POST", "/api/ciphers", 400, 1);
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert!(!v.snapshot().await.collections.iter().any(|c| c.id == "work"), "the view goes back");
    assert!(!v.fake.with(|s| s.sync["ciphers"].as_array().unwrap().iter().any(|c| c["type"] == 2)), "no note");
}
