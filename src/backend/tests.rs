//! The write path end to end, against an in-process fake Bitwarden server.

#![expect(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::Backend;
use super::BackendError;
use super::bitwarden::BitwardenBackend;
use super::ops::{Loaded, Op, QUEUE_FORMAT, read_formats, unseal};
use super::registry::Registry;
use super::runner::Effect;
use crate::bw::crypto::{KdfParams, SymmetricKey, derive_master_key};
use crate::bw::fields::field_names;
use crate::bw::scan::{Keys, Scan, scan};
use crate::bw::write::{Patch, ValueChange};
use crate::config::{Config, Credentials, Paths};
use crate::model::{Attributes, ItemData, Snapshot};

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
    backend: Arc<BitwardenBackend>,
    _dir: tempfile::TempDir,
    dir: std::path::PathBuf,
}

fn enc_fields(k: &SymmetricKey, fields: &[(&str, &str)]) -> Value {
    Value::Array(
        fields
            .iter()
            .map(|(n, v)| json!({ "type": 0, "name": k.encrypt_str(n), "value": k.encrypt_str(v), "linkedId": null }))
            .collect(),
    )
}

/// A login the user marked by hand, with a field of another tool.
fn hand_marked(k: &SymmetricKey, cid: &str, id: &str) -> Value {
    json!({
        "id": cid, "type": 1, "organizationId": null, "folderId": null, "revisionDate": REV, "creationDate": REV,
        "deletedDate": null, "name": k.encrypt_str("GitHub"), "notes": null, "favorite": false, "reprompt": 0,
        "login": {
            "username": k.encrypt_str("me"), "password": k.encrypt_str("pw"), "totp": null,
            "uris": [{ "uri": k.encrypt_str("https://github.com"), "match": null }],
        },
        "passwordHistory": null,
        "fields": enc_fields(k, &[("bwss:id", id), ("bwss:attr:service", "git"), ("obsidian:id", "o1")]),
    })
}

fn registry_note(k: &SymmetricKey, cid: &str, notes: &str) -> Value {
    json!({
        "id": cid, "type": 2, "organizationId": null, "folderId": null, "revisionDate": REV, "creationDate": REV,
        "deletedDate": null, "name": k.encrypt_str("bwss collections"), "notes": k.encrypt_str(notes),
        "secureNote": { "type": 0 }, "passwordHistory": null,
        "fields": enc_fields(k, &[("bwss:id", "_collections"), ("bwss:kind", "collections")]),
    })
}

async fn vault(ciphers: Vec<Value>, user: SymmetricKey) -> Vault {
    let master = derive_master_key(PASSWORD, EMAIL, KdfParams::Pbkdf2 { iterations: ITERATIONS }).unwrap();
    let protected = SymmetricKey::stretch(&master).encrypt(&user.to_bytes());
    let sync = json!({ "profile": { "id": "user1", "key": protected }, "folders": [], "ciphers": ciphers });
    let (fake, url) = Fake::start(sync);
    let dir = tempfile::tempdir().unwrap();
    let identity_origin = crate::bw::api::origin_of(&url).unwrap();
    let config = Config { server_url: url, email: EMAIL.into(), profile: Some("p".into()), ..Config::default() };
    let paths = paths_in(dir.path());
    let creds = Credentials { identity_origin, client_id: "id".into(), client_secret: Zeroizing::new("secret".into()) };
    let backend = Arc::new(BitwardenBackend::new(&config, creds, &paths).unwrap());
    backend.unlock(PASSWORD).await.unwrap();
    let keys = Keys { mark: user.derive("value-mark"), user };
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

    fn marked(&self, cid: &str) -> crate::bw::scan::MarkedItem {
        match scan(&self.fake.cipher(cid), &self.keys) {
            Scan::Marked(m) => *m,
            other => panic!("expected {cid} marked, got {other:?}"),
        }
    }

    async fn queued(&self) -> usize {
        self.backend.queue.lock().await.len()
    }

    /// The ops in queue.json, opened with the queue key.
    fn queue_file(&self) -> usize {
        match read_formats(&self.dir.join("state/queue.json"), "legacy", &[QUEUE_FORMAT]) {
            Loaded::Ok(v) => unseal(&v, &super::bitwarden::queue_key(&self.keys.user)).unwrap().len(),
            Loaded::Missing => 0,
            _ => panic!("queue.json cannot be read"),
        }
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
    let k = SymmetricKey::generate();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
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
    let k = SymmetricKey::generate();
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
    let k = SymmetricKey::generate();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k.clone()).await;

    // Another device renamed the item: bwss's label lands on the fresh copy.
    let renamed = k.encrypt_str("Renamed elsewhere");
    v.fake.with(|s| s.before_put = Some(Box::new(move |c: &mut Value| c["name"] = json!(renamed))));
    let mut item = v.item("gh").await;
    item.label = "Mine".into();
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.dec(&v.fake.cipher("c1")["name"]), "Renamed elsewhere");
    assert_eq!(v.marked("c1").item.label, "Mine");

    // Another device changed the password: bwss does not overwrite it.
    let other = k.encrypt_str("theirs");
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
    let k = SymmetricKey::generate();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
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
    let k = SymmetricKey::generate();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k.clone()).await;
    v.fake.with(|s| s.down = true);
    let mut item = v.item_offline("gh").await;
    item.secret = Zeroizing::new(b"queued".to_vec());
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.queued().await, 1);

    // Another client renames the item; saving re-encrypts every value with
    // a fresh IV, the unchanged password included.
    let (name, pw) = (k.encrypt_str("Renamed"), k.encrypt_str("pw"));
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
    let k = SymmetricKey::generate();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k.clone()).await;
    v.fake.with(|s| s.down = true);
    let mut item = v.item_offline("gh").await;
    item.secret = Zeroizing::new(b"ours".to_vec());
    item.label = "Queued".into();
    item.attributes.insert("user".into(), "me".into());
    item.acl.push("/usr/bin/app".into());
    v.backend.put_item(&item).await.unwrap();
    assert_eq!(v.queued().await, 1);

    // Another device changes the password meanwhile.
    let theirs = k.encrypt_str("theirs");
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
    let k = SymmetricKey::generate();
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
    assert_eq!(v.item_offline("gh").await.label, "GitHub");
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
    let k = SymmetricKey::generate();
    let other = json!({
        "id": "c2", "type": 2, "organizationId": null, "folderId": null, "revisionDate": REV, "creationDate": REV,
        "deletedDate": null, "name": k.encrypt_str("Other"), "notes": null, "secureNote": { "type": 0 },
        "passwordHistory": null, "fields": enc_fields(&k, &[("bwss:id", "x"), ("bwss:password", "s")]),
    });
    let v = vault(vec![hand_marked(&k, "c1", "gh"), other], k).await;
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
    assert_eq!(v.queued().await, 2, "a change to an item that cannot be read waits");
    assert_eq!(v.queue_file(), 2);
    // Also after a new unlock, when nothing is held yet.
    v.backend.lock().await;
    v.backend.unlock(PASSWORD).await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!((v.queued().await, v.queue_file()), (2, 2));

    // Readable again: the change goes through; the delete of a gone item is
    // dropped.
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
    let k = SymmetricKey::generate();
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
    let k = SymmetricKey::generate();
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
    let flush = tokio::spawn(async move { backend.refresh().await });
    tokio::task::spawn_blocking(move || reached.recv().unwrap()).await.unwrap();
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
    let _ = flush.await.unwrap();
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
    let k = SymmetricKey::generate();
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
    let k = SymmetricKey::generate();
    let v = vault(vec![registry_note(&k, "r1", r#"{"work":{"label":"Work","created":5}}"#)], k.clone()).await;
    v.fake.with(|s| s.down = true);
    v.backend.delete_collection("work", &[]).await.unwrap();
    assert_eq!(v.queued().await, 1);

    // Another device deleted and created it again meanwhile.
    let notes = k.encrypt_str(r#"{"work":{"label":"Work again","created":100}}"#);
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
    let k = SymmetricKey::generate();
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
    let k = SymmetricKey::generate();
    let mut clone = hand_marked(&k, "c2", "gh");
    clone["creationDate"] = json!("2026-06-01T00:00:00Z");
    let twin = hand_marked(&k, "c3", "twin");
    let v = vault(vec![hand_marked(&k, "c1", "gh"), clone, twin], k).await;
    let status = v.backend.describe().await;
    assert!(status.contains("duplicate id gh: 1 items ignored"), "{status}");
    assert!(status.contains("possible duplicates: GitHub (gh), GitHub (twin)"), "{status}");
}

#[tokio::test]
async fn a_write_read_from_the_server_replaces_a_queued_one() {
    let k = SymmetricKey::generate();
    let v = vault(vec![hand_marked(&k, "c1", "gh"), hand_marked(&k, "c2", "x")], k.clone()).await;
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
    let theirs = k.encrypt_str("theirs");
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
    let k = SymmetricKey::generate();
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
    assert_eq!((m.source, m.item.secret.as_slice()), (crate::bw::scan::ValueSource::Field, &b"text"[..]));
}

#[tokio::test]
async fn a_write_out_of_date_on_every_attempt_is_retried_never_lost() {
    let k = SymmetricKey::generate();
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
    let k = SymmetricKey::generate();
    let v = vault(vec![], k.clone()).await;
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    let cid = v.fake.with(|s| s.sync["ciphers"][0]["id"].as_str().unwrap().to_owned());
    let item = v.item("n1").await;

    // While bwss saves the stripped item, another device adds a note field:
    // the save is out of date, and the retry keeps that field.
    let (name, value) = (k.encrypt_str("note"), k.encrypt_str("mine"));
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
    let user = SymmetricKey::generate();
    let v = vault(vec![], user.clone()).await;
    match v.backend.acl_trust().await.unwrap() {
        super::AclTrust::PerDevice(key) => {
            assert_eq!(key.to_bytes(), user.derive("acl-confirm").to_bytes());
            assert_ne!(key.to_bytes(), user.to_bytes());
        }
        super::AclTrust::Local => panic!("synced lines must be confirmed per device"),
    }
    v.backend.lock().await;
    assert!(matches!(v.backend.acl_trust().await, Err(BackendError::Locked)));
}

// --- what goes wrong on the server ---------------------------------------------

impl Vault {
    async fn has_item(&self, id: &str) -> bool {
        self.backend.state.lock().await.as_ref().unwrap().built.marked.contains_key(id)
    }

    async fn logged_in(&self) -> bool {
        self.backend.api.lock().await.is_logged_in()
    }

    /// Another device adds a field to `cid`. The server's revision stays
    /// as it is, so a refresh does not look at it.
    fn add_field(&self, cid: &str, name: &str, value: &str) {
        let field = json!({
            "type": 0, "name": self.keys.user.encrypt_str(name), "value": self.keys.user.encrypt_str(value),
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
async fn lock_during<T: Send + 'static>(
    v: &Vault,
    method: &str,
    path: &str,
    op: impl std::future::Future<Output = T> + Send + 'static,
) -> T {
    let mut gate = Gate::hold(&v.fake, method, path);
    let running = tokio::spawn(op);
    gate.arrived().await;
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
    let out = running.await.unwrap();
    locking.await.unwrap();
    out
}

async fn github() -> Vault {
    let k = SymmetricKey::generate();
    vault(vec![hand_marked(&k, "c1", "gh")], k).await
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
        assert_eq!(v.item_offline("gh").await.label, "GitHub", "{status}: the refused change is not shown");
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
    assert_eq!(v.item_offline("gh").await.label, "GitHub");
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
    let v = vault(vec![], SymmetricKey::generate()).await;
    let backend = v.backend.clone();
    let result =
        lock_during(&v, "POST", "/api/folders", async move { backend.put_item(&new_item("n1", "login")).await }).await;
    assert!(matches!(result, Err(BackendError::Locked)), "{result:?}");
    assert_eq!(v.fake.count("POST", "/api/folders"), 1);
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flush_stops_when_the_keyring_locks_and_the_write_stays_on_disk() {
    let v = vault(vec![], SymmetricKey::generate()).await;
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
    let v = vault(vec![], SymmetricKey::generate()).await;
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
    assert!(matches!(&err, BackendError::Unavailable(m) if m.contains("no revisionDate")), "{err}");
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

    // With the session gone and the server down, it is queued, to be applied
    // once the item can be read.
    v.backend.api.lock().await.logout();
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
    assert_eq!(shown.items[0].label, "GitHub");
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert_eq!(v.fake.count("PUT", "/api/ciphers/c1") - puts, 1, "refused once, not sent again");
    assert!(!v.names("c1").iter().any(|n| n == "bwss:label"));
}

#[tokio::test]
async fn ops_that_were_done_before_send_nothing() {
    let v = vault(vec![], SymmetricKey::generate()).await;
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    let item = v.item("n1").await;
    let (posts, puts) = (v.fake.count("POST", "/api/ciphers"), v.fake.count("PUT", "/api/ciphers"));

    // A queued create that was accepted before (just before a lock).
    let create = Op::Create { id: "n1".into(), collection: "login".into(), item };
    let effect = v.backend.run(&create).await.unwrap();
    assert!(matches!(effect, Effect::Nothing), "{effect:?}");

    // A patch with no change.
    let empty = Op::Patch(Patch {
        id: "n1".into(),
        base_revision: REV.into(),
        set: vec![],
        remove: vec![],
        acl_add: vec![],
        value: ValueChange::Keep,
        cipher_id: None,
    });
    let effect = v.backend.run(&empty).await.unwrap();
    assert!(matches!(effect, Effect::Nothing), "{effect:?}");
    assert_eq!((v.fake.count("POST", "/api/ciphers"), v.fake.count("PUT", "/api/ciphers")), (posts, puts));
}

#[tokio::test]
async fn a_new_item_the_server_refuses_is_rejected() {
    let v = vault(vec![], SymmetricKey::generate()).await;
    v.fake.fault("POST", "/api/ciphers", 400, 1);
    let err = v.backend.put_item(&new_item("n1", "login")).await.unwrap_err();
    assert!(matches!(&err, BackendError::Rejected(m) if m.contains("HTTP 400")), "{err}");
    assert!(!v.has_item("n1").await);
    assert_eq!(v.queue_sizes().await, (0, 0));
}

#[tokio::test]
async fn a_folder_the_server_creates_without_an_id_is_not_used_yet() {
    let v = vault(vec![], SymmetricKey::generate()).await;
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
    let v = vault(vec![], SymmetricKey::generate()).await;
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
    let k = SymmetricKey::generate();
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
    let junk = v.keys.user.encrypt_str("not json");
    v.fake.with(|s| s.before_put = Some(Box::new(move |c: &mut Value| c["notes"] = json!(junk))));
    let err = v.backend.create_collection("Work").await.unwrap_err();
    assert!(
        matches!(&err, BackendError::Unavailable(m) if m.starts_with("the collection registry cannot be read")),
        "{err}"
    );
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 0);

    // It lost its marks: a new registry note is started, with what is known.
    let v = with_registry().await;
    v.fake.with(|s| s.before_put = Some(Box::new(|c: &mut Value| c["fields"] = json!([]))));
    v.backend.create_collection("Work").await.unwrap();
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1);
    assert_eq!(newest_registry(&v).0.into_keys().collect::<Vec<_>>(), ["home", "work"]);
}

#[tokio::test]
async fn a_registry_note_with_a_password_field_is_never_rewritten() {
    let k = SymmetricKey::generate();
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
    let v = vault(vec![], SymmetricKey::generate()).await;
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
    let junk = v.keys.user.encrypt_str("not json");
    v.edit_elsewhere("r1", |c| c["notes"] = json!(junk));
    v.backend.refresh().await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (1, 1), "never written over, never dropped");
    assert_eq!(v.fake.count("PUT", "/api/ciphers/r1") - puts, 1, "only the out-of-date attempt");

    // Fixed: the change goes through.
    let fixed = v.keys.user.encrypt_str(HOME);
    v.edit_elsewhere("r1", |c| c["notes"] = json!(fixed));
    v.backend.refresh().await.unwrap();
    v.backend.refresh().await.unwrap();
    assert_eq!(v.queue_sizes().await, (0, 0));
    assert!(Registry::try_parse(&v.dec(&v.fake.cipher("r1")["notes"])).unwrap().0.contains_key("work"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registry_found_unreadable_while_its_folder_is_made_is_not_written() {
    let v = vault(vec![], SymmetricKey::generate()).await;
    let mut gate = Gate::hold(&v.fake, "POST", "/api/folders");
    let backend = v.backend.clone();
    let creating = tokio::spawn(async move { backend.create_collection("Work").await });
    gate.arrived().await;
    // The keyring is rebuilt meanwhile, and the registry is now unreadable.
    v.backend.state.lock().await.as_mut().unwrap().built.registry_unreadable = true;
    gate.open();
    let err = creating.await.unwrap().unwrap_err();
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
    v.fake.fault("POST", "/identity/accounts/prelogin", 400, 1);
    let err = v.backend.unlock(PASSWORD).await.unwrap_err();
    assert!(matches!(&err, BackendError::Rejected(m) if m.contains("HTTP 400")), "{err}");

    v.fake.with(|s| s.sync["profile"]["key"] = Value::Null);
    let err = v.backend.unlock(PASSWORD).await.unwrap_err();
    assert!(matches!(&err, BackendError::Unavailable(m) if m.contains("without account key")), "{err}");
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
    let k = SymmetricKey::generate();
    let mut card = hand_marked(&k, "c4", "card");
    card["type"] = json!(3);
    let v = vault(vec![hand_marked(&k, "c1", "gh"), card], k).await;
    let status = v.backend.describe().await;
    assert!(status.contains("\nskipped: c4: item type 3 is not supported"), "{status}");
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
    assert_eq!(v.item_offline("gh").await.label, "GitHub");
}

#[tokio::test]
async fn a_vault_sync_without_a_cipher_list_still_takes_writes() {
    let v = vault(vec![], SymmetricKey::generate()).await;
    v.fake.with(|s| {
        s.rev += 1;
        s.sync.as_object_mut().unwrap().remove("ciphers");
    });
    v.backend.refresh().await.unwrap();
    assert!(v.backend.state.lock().await.as_ref().unwrap().sync.get("ciphers").is_none());
    v.backend.put_item(&new_item("n1", "login")).await.unwrap();
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 1);
    // The server's answer had nowhere to go in the cache: the next sync shows the item.
    assert_eq!(v.item("n1").await.label, "App token");
}

#[tokio::test]
async fn deleting_a_collection_that_only_items_name_leaves_no_registry_entry() {
    let v = vault(vec![], SymmetricKey::generate()).await;
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
    let v = vault(vec![], SymmetricKey::generate()).await;
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
    let v = vault(vec![], SymmetricKey::generate()).await;
    let err = v.backend.create_collection(&big).await.unwrap_err();
    assert!(matches!(&err, BackendError::Rejected(m) if m.contains("too large")), "{err}");
    assert_eq!(v.fake.count("POST", "/api/ciphers"), 0);
    assert_eq!(v.queued().await, 0);
}

#[tokio::test]
async fn a_collection_made_again_is_newer_than_its_tombstone() {
    let k = SymmetricKey::generate();
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
    let k = SymmetricKey::generate();
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
