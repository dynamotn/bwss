//! The write path end to end, against an in-process fake Bitwarden server.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::Backend;
use super::BackendError;
use super::bitwarden::BitwardenBackend;
use super::ops::{Loaded, read_versioned, unseal};
use super::registry::Registry;
use crate::bw::crypto::{KdfParams, SymmetricKey, derive_master_key};
use crate::bw::fields::field_names;
use crate::bw::scan::{Keys, Scan, scan};
use crate::config::{Config, Credentials, Paths};
use crate::model::{Attributes, ItemData, Snapshot};

const EMAIL: &str = "a@b.c";
const PASSWORD: &str = "pw";
const ITERATIONS: u32 = 5_000;
const REV: &str = "2026-01-01T00:00:00Z";

type Hook = Box<dyn FnOnce(&mut Value) + Send>;

struct Server {
    sync: Value,
    rev: u64,
    down: bool,
    /// Every item update fails with 503.
    fail_puts: bool,
    /// The next this many item updates find the cipher changed elsewhere.
    stale_puts: usize,
    requests: Vec<(String, String)>,
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
            None => self.sync["ciphers"].as_array_mut().expect("ciphers").push(body.clone()),
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
    let config = Config { server_url: url, email: EMAIL.into(), ..Config::default() };
    let paths = Paths {
        config: dir.path().join("config.toml"),
        credentials: dir.path().join("credentials.toml"),
        cache: dir.path().join("cache"),
        state: dir.path().join("state"),
    };
    let creds = Credentials { client_id: "id".into(), client_secret: "secret".into() };
    let backend = Arc::new(BitwardenBackend::new(&config, creds, &paths).unwrap());
    backend.unlock(PASSWORD).await.unwrap();
    let keys = Keys { mark: user.derive("value-mark"), user };
    Vault { keys, fake, backend, dir: dir.path().to_owned(), _dir: dir }
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

    /// The ops in queue.json, opened with the user key.
    fn queue_file(&self) -> usize {
        match read_versioned(&self.dir.join("state/queue.json"), "legacy") {
            Loaded::Ok(v) => unseal(&v, &self.keys.user).unwrap().len(),
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

#[cfg(unix)]
#[tokio::test]
async fn a_change_that_cannot_be_kept_on_disk_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let k = SymmetricKey::generate();
    let v = vault(vec![hand_marked(&k, "c1", "gh")], k).await;
    v.fake.with(|s| s.down = true);
    let state = v.dir.join("state");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::File::create(state.join("probe")).is_ok() {
        return; // permissions not enforced (running as root)
    }
    let item = ItemData { label: "Queued".into(), ..v.item_offline("gh").await };
    let result = v.backend.put_item(&item).await;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(&result, Err(BackendError::Unavailable(_))), "{result:?}");
    assert_eq!(v.queued().await, 0, "a change not on disk is not kept in memory either");
    assert_eq!(v.item_offline("gh").await.label, "GitHub");
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
    while v.backend.state.lock().await.is_some() {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
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
