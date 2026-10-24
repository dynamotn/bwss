//! Performance budgets, run with `cargo test --release perf -- --ignored --nocapture`.
//! They catch order-of-magnitude regressions; the timings are printed.

#![expect(clippy::unwrap_used, reason = "tests")]

use std::time::Instant;

use zeroize::Zeroizing;

use crate::backend::bitwarden::build;
use crate::bw::crypto::{KdfParams, SymmetricKey, derive_master_key};
use crate::bw::scan::{Keys, Scan, scan};
use crate::bw::write::new_note;
use crate::keyring::Keyring;
use crate::model::{Attributes, ItemData, Snapshot};
use crate::session::{DH_AES, Session};

fn time<T>(name: &str, budget_ms: u128, f: impl FnOnce() -> T) -> T {
    let t = Instant::now();
    let out = f();
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("[perf] {name}: {ms:.1} ms (budget {budget_ms} ms)");
    assert!(ms < budget_ms as f64, "{name} took {ms:.1} ms");
    out
}

fn item(i: usize) -> ItemData {
    let mut attributes = Attributes::new();
    attributes.insert("service".into(), format!("svc-{}", i % 100));
    attributes.insert("user".into(), format!("user-{i}"));
    ItemData {
        id: format!("id{i}"),
        collection: "login".into(),
        label: format!("item {i}"),
        attributes,
        secret: Zeroizing::new(format!("secret-{i}").into_bytes()),
        content_type: "text/plain".into(),
        created: 1,
        modified: 1,
        acl: vec!["/usr/bin/app".into()],
    }
}

#[test]
#[ignore = "performance; run explicitly"]
fn perf_budgets() {
    time("pbkdf2-600k", 3_000, || derive_master_key("pw", "a@b.c", KdfParams::Pbkdf2 { iterations: 600_000 }).unwrap());
    time("argon2id-64m-t3-p4", 5_000, || {
        derive_master_key("pw", "a@b.c", KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 }).unwrap()
    });

    let key = SymmetricKey::generate();
    let keys = Keys { mark: key.derive("value-mark"), user: key };
    let ciphers: Vec<_> = time("new-note-10000-items", 5_000, || {
        (0..10_000)
            .map(|i| {
                let mut body = new_note(&item(i), Some("f"), &keys).unwrap();
                body.insert("id".into(), format!("c{i}").into());
                body.insert("revisionDate".into(), "2026-10-23T00:00:00Z".into());
                serde_json::Value::Object(body)
            })
            .collect()
    });
    let marked = time("scan-10000-items", 5_000, || {
        ciphers.iter().filter(|c| matches!(scan(c, &keys), Scan::Marked(_))).count()
    });
    assert_eq!(marked, 10_000);
    let sync = serde_json::json!({ "ciphers": ciphers });
    let built = time("build-10000-items", 5_000, || build(&sync, &keys, None));
    assert_eq!(built.snapshot.items.len(), 10_000);
    time("rescan-10000-unchanged", 5_000, || build(&sync, &keys, Some(&built)));
    let decoded = built.snapshot.items;

    let mut k = Keyring::new(None);
    time("load-10000-items", 1_000, || k.load(Snapshot { collections: vec![], items: decoded }));
    let mut q = Attributes::new();
    q.insert("service".into(), "svc-42".into());
    let (hits, _) = time("search-10000-items", 50, || k.search(&q, None));
    assert_eq!(hits.len(), 100);
    time("search-1000x", 2_000, || {
        for _ in 0..1_000 {
            k.search(&q, None);
        }
    });

    let p = num_bigint::BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16).unwrap();
    let client = num_bigint::BigUint::from(2u8).modpow(&num_bigint::BigUint::from(123_456_789u64), &p);
    let (s, _) = time("dh-open-session", 100, || Session::open(DH_AES, &client.to_bytes_be()).unwrap());
    time("dh-encrypt-10000-secrets", 1_000, || {
        for _ in 0..10_000 {
            s.encrypt(b"a typical secret value");
        }
    });
}
