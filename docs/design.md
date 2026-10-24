# bwss — design and verification

This document covers how `bwss` works, why it is built that way, and how it
was verified. The user-facing summary is in [`README.md`](../README.md), and
the original plan is in [`plan.md`](plan.md).

At a glance:

- Rust 2024, roughly 3,900 lines in `src/`. A single binary provides the
  daemon and the CLI.
- Main dependencies:
  - `zbus` 6 (D-Bus, on tokio);
  - `reqwest` 0.13 with rustls;
  - RustCrypto: `aes` 0.9, `cbc`, `hmac`, `hkdf`, `pbkdf2`, `argon2`, `sha2`;
  - `num-bigint` for the Diffie-Hellman session.
- Implements `org.freedesktop.Secret.Service`, `.Collection`, `.Item`,
  `.Session` and `.Prompt`, plus a private control interface,
  `io.github.dynamotn.bwss.Control1`.

## Contents

1. [Goal](#1-goal)
2. [Architecture](#2-architecture)
3. [Storage mapping](#3-storage-mapping)
4. [Locking, unlocking and the locked index](#4-locking-unlocking-and-the-locked-index)
5. [Sessions (transport encryption)](#5-sessions-transport-encryption)
6. [Prompts](#6-prompts)
7. [Per-application access control](#7-per-application-access-control)
8. [Sync, offline mode and the write queue](#8-sync-offline-mode-and-the-write-queue)
9. [CLI and integration](#9-cli-and-integration)
10. [Security model](#10-security-model)
11. [Verification](#11-verification)
12. [Portability](#12-portability)
13. [Performance](#13-performance)
14. [Limitations and future work](#14-limitations-and-future-work)

---

## 1. Goal

Give Linux the macOS Keychain experience, with Bitwarden as the store:

| Keychain | bwss |
|---|---|
| Every app uses one API | Every Secret Service client: libsecret/`secret-tool`, Chromium and Electron, NetworkManager, python-keyring and `secretstorage`, `oo7` |
| Unlock once per session | A pinentry prompt for the Bitwarden master password; `bwss unlock` for scripts |
| "Always allow" per app | An item ACL of executable paths, with a confirmation prompt for anyone else |
| Lock on demand or after idle | `Lock`, `LockService`, `bwss lock`, `idle_lock_minutes`; keys are zeroised |
| Works offline | Encrypted cache of the last sync, plus a queue of pending writes |
| iCloud Keychain sync | Bitwarden: periodic pull, write-through push, revision checks |

## 2. Architecture

```mermaid
flowchart TB
  subgraph clients
    ST[secret-tool / libsecret]
    PY[python secretstorage]
    APP[Chromium, VS Code, NM ...]
  end
  clients -- session bus --> DB
  subgraph bwss daemon
    DB[dbus.rs<br/>Service / Collection / Item /<br/>Session / Prompt / Control]
    D[daemon.rs<br/>object tree, signals,<br/>unlock, ACL, item ops]
    K[keyring.rs<br/>in-memory state, search,<br/>locked index]
    S[session.rs<br/>plain + DH-AES]
    P[prompter.rs<br/>pinentry / Assuan]
    A[acl.rs<br/>caller → /proc/pid/exe]
    B[backend: memory.rs | bitwarden.rs]
    DB --> D --> K
    DB --> S
    D --> P
    DB --> A
    D --> B
  end
  B -- bw/api.rs, bw/items.rs, bw/crypto.rs --> BW[(Bitwarden / Vaultwarden)]
  B --> FS[(~/.cache/bwss: sync.json, locked-index.json<br/>~/.local/state/bwss: queue.json, device-id)]
```

| Module | Role |
|---|---|
| `bw/crypto.rs` | PBKDF2/Argon2id with bounds, HKDF-Expand stretch, `SymmetricKey` (zeroized on drop), EncString type 2 |
| `bw/api.rs` | URL resolution (https or loopback only), prelogin, API-key login, sync, folder and item writes, `encryptedFor`, no redirects, error shaping |
| `bw/items.rs` | Bitwarden login ↔ Secret Service item (fields `bwss:*`), pass-through of unknown properties, password history, size limits |
| `model.rs` | `ItemData`, `CollectionData`, `Snapshot`, path segments |
| `keyring.rs` | In-memory collections and items, lock state, search, diffing, persisted locked index |
| `session.rs` | `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7` |
| `prompter.rs` | pinentry client: password with retry, and a two-step confirmation |
| `acl.rs` | Caller executable through `GetConnectionUnixProcessID` and `/proc/<pid>/exe` |
| `daemon.rs` | Shared state; exporting objects and signals; unlock flows; authorization; item operations |
| `dbus.rs` | The D-Bus interfaces: thin wrappers over `Daemon` |
| `backend/` | `Backend` trait, `MemoryBackend` (tests, demos), `BitwardenBackend` |
| `config.rs`, `fsutil.rs`, `main.rs` | XDG paths, private atomic writes, CLI, background tasks |

## 3. Storage mapping

| Secret Service | Bitwarden |
|---|---|
| Collection `login` (alias `default`) | folder `<root>`, by default `secret-service` |
| Collection *X* | folder `<root>/X` |
| Collection `session` | memory only; never stored, never locked |
| Item | a **login** item (secure notes made by other clients are also read) |
| Label | item name |
| Secret | `login.password`. Base64 plus `bwss:encoding=base64` when the bytes are not UTF-8. It moves to `notes` (with `bwss:location=notes`) when its encrypted form exceeds the 5,000-character password limit, and is refused above the 10,000-character notes limit. |
| Attributes | text fields `bwss:attr:<name>` |
| Bookkeeping | `bwss:id` (stable id shared by all devices), `bwss:content-type`, `bwss:acl` (hidden field), `bwss:created` |
| Collection `vault` (`whole_vault = true`) | every other personal login and secure note, in any folder or none; read-only |

Notes:

- **Why logins**: the secret is masked and copyable in every Bitwarden
  client, and password history comes for free.
- **Edits** pass the item through as the server sent it, minus response-only
  metadata. They keep foreign fields, username, URIs, attachments and
  unknown properties, prepend the old password to `passwordHistory`, and
  send `lastKnownRevisionDate` and `encryptedFor`.
- **Per-item keys** (`cipher.key`) are used for reading and kept on write.
- **Items without `bwss:id`** (made by other clients) get the id `c<cipher
  id>`.
- **The whole vault** (`whole_vault = true`):
  - items outside `<root>` and its sub-folders land in the `vault`
    collection. Their attributes are derived: `bwss:name` (item name),
    `bwss:username`, `bwss:uri` (the first URI) and `bwss:folder`, each
    left out when empty. The `bwss:` prefix keeps an app's ordinary query
    (`service=…`, `username=…`) from matching them by accident.
  - they are read-only: creating, changing or deleting them, and deleting
    the collection, fail with `NotSupported`, before any access prompt.
  - their "Always allow" rules are not written into the item (it is not
    ours) but into `~/.local/state/bwss/vault-acl`, encrypted with the user
    key, so another process cannot grant itself access by editing the
    file. Those rules stay on the machine that made them.
  - a sub-folder `<root>/Vault` would clash with the collection id; it is
    skipped with a warning and its items show up in `vault`.
  - the locked index covers them too, so it reveals how many items the
    vault holds (still never labels, values or secrets).
  - organization items are still not read.
- **Duplicates**: duplicate folder names resolve to the lowest folder id,
  and duplicate `bwss:id`s keep the first item. Both rules make every device
  agree.

## 4. Locking, unlocking and the locked index

- One master password unlocks the whole keyring. All persistent collections
  share the same lock; `session` never locks.
- **Unlock paths**:
  - `Service.Unlock` returns a prompt, and `Prompt.Prompt` asks through
    pinentry, up to 3 attempts, showing "Wrong password, try again."
  - `bwss unlock` uses the control interface. Failures are delayed by 2 s to
    slow down guessing.
- **Locking** (`Lock`, `LockService`, `bwss lock`, idle timeout, SIGTERM)
  drops every decrypted item and the user key, and logs out of the API.
- **Locked index**:
  - *The problem*: libsecret only unlocks what a search reported as
    *locked*. With attributes encrypted, a locked daemon could not report
    anything, and `secret-tool lookup` would silently fail after a restart.
  - *The fix*, as in gnome-keyring: while unlocked, bwss maintains
    `~/.cache/bwss/locked-index.json` with, per item, its id, its collection
    and SHA-256(salt ‖ name ‖ 0 ‖ value) of each attribute. The salt is
    random and per install.
  - *The cost*: the file reveals that items exist, and lets someone holding
    it test guesses of attribute values. It never contains secrets or
    labels.

## 5. Sessions (transport encryption)

- **`plain`**: no transport encryption.
- **`dh-ietf1024-sha256-aes128-cbc-pkcs7`**, as in libsecret and
  gnome-keyring:
  - RFC 2409 group 2 with generator 2, and a fresh 1024-bit private
    exponent per session;
  - shared secret left-padded to 128 bytes, then HKDF-SHA256 with no salt
    and no info, giving a 16-byte AES key;
  - AES-128-CBC-PKCS7 with a random IV per secret, sent as `parameters`.
- **Public key validation**: client keys outside (1, p−1) are rejected.
- **Ownership**: a session belongs to the client that opened it.
  `GetSecret(s)` and `CreateItem`/`SetSecret` refuse a session owned by
  another bus name.
- **Limit**: at most 4,096 open sessions; the oldest are evicted.

## 6. Prompts

`prompter.rs` speaks the Assuan protocol to any pinentry program (`prompter`
in the config):

- **Master password**: `SETTITLE`/`SETDESC`/`SETPROMPT`/`SETERROR`, then
  `GETPIN`. A cancel returns `None`.
- **Access confirmation** is fail-closed and asked in two steps.
  1. "Allow / Deny" (`CONFIRM`): **only an explicit OK allows**.
  2. "Always allow / Only this time": only an explicit OK remembers.

  An earlier version used pinentry's third button (`SETNOTOK`) for "Always".
  Some pinentries report other buttons with the same error code, which
  turned a refusal into a permanent grant. The review caught this and it was
  changed.
- **Timeout**: every prompt has a 120 s limit.
- **Completed signal**: `Prompt.Completed` must carry a result of the type a
  success would have (`ao` for an unlock, `o` for a create), even when the
  prompt was dismissed. libsecret 0.21 hangs forever when the type is wrong;
  the end-to-end suite caught this.

## 7. Per-application access control

- **Identity**: the caller's unique bus name, through
  `GetConnectionUnixProcessID`, then `/proc/<pid>/exe` (with the
  " (deleted)" suffix stripped).
- **What is checked**: reads (`GetSecret`, `GetSecrets`), changes
  (`SetSecret`, `Label`, `Attributes`, `CreateItem` with `replace`), deletes
  (`Item.Delete`, and `Collection.Delete` for every item it contains).
- **New items** get their creator in `bwss:acl`, so the creator is never
  asked. Items of the `vault` collection have no creator: every app is
  asked the first time.
- **"Always allow"** appends the executable to the ACL and stores it in
  Bitwarden. The decision therefore follows the item to every device,
  matched by executable path.
- **Exemptions**: `acl = "off"` gives gnome-keyring behaviour, and the
  `session` collection is exempt.
- **Limits**: same-user processes can ptrace each other, and interpreters
  share one identity (`/usr/bin/python3`). This is a speed bump against
  quiet cross-app reads, not a sandbox.

## 8. Sync, offline mode and the write queue

- **Unlock online**: prelogin, API-key login, `/sync`, decrypt the user key.
  The sync response (still ciphertext) and the KDF parameters are cached in
  `sync.json` (mode 0600).
- **Unlock offline**: when the network fails with a transient error
  (connection, 429, 5xx), the cache is used. The wrong-password check is the
  same, because it is the MAC of the protected user key.
- **Writes**:
  - Online, they go straight to the server, and the answer is folded into
    the cached sync. The cache file is rewritten after every write, so what
    was written survives an offline restart.
  - On a transient failure, the encrypted request is appended to
    `~/.local/state/bwss/queue.json`, and any later writes queue behind it
    so order is kept.
  - On an out-of-date rejection, bwss refreshes and re-applies the edit
    (last writer wins, as in the keychain).
- **Refresh** (every `sync_interval_seconds`, default 300, and on
  `bwss sync`):
  - it flushes the queue first, then fetches `/sync`;
  - when ciphers or folders changed, it rebuilds the snapshot, and the
    daemon emits `ItemCreated`/`ItemChanged`/`ItemDeleted` and
    `CollectionCreated`/`CollectionDeleted`.
- **Queued creates**: a queued create becomes an update once an earlier
  queued create of the same item has reached the server.
- **Deleting an item** sends it to the Bitwarden trash. If it never reached
  the server, it is simply dropped from the queue.

## 9. CLI and integration

```
bwss daemon [--replace]       serve org.freedesktop.secrets and io.github.dynamotn.bwss
bwss unlock [--password-stdin]
bwss lock | sync | status
bwss login --email E [--server URL] --client-id ID [--client-secret-stdin]
```

- **Bus names**: `org.freedesktop.secrets` is requested with
  `DO_NOT_QUEUE | ALLOW_REPLACEMENT`, plus `REPLACE_EXISTING` when
  `--replace` is given. If another provider owns the name, bwss exits with a
  clear message.
- **Files**:
  - `contrib/bwss.service`: systemd user unit, `Type=dbus`, with hardening
    options;
  - `contrib/org.freedesktop.secrets.service`: D-Bus activation through
    systemd;
  - `contrib/config.example.toml`.
- **Config**: `config.toml` uses `deny_unknown_fields`.
- **Credentials**: `credentials.toml` must be mode 0600 or bwss refuses to
  start. `bwss login` writes both files with 0600 permissions, atomically.

## 10. Security model

| Asset | Protection |
|---|---|
| Master password | Used locally only; zeroized buffers; never sent |
| User key | Memory only while unlocked; `Zeroize` on drop; dropped on lock |
| API key | 0600 file; sent only to the configured identity host; https required except loopback; **redirects disabled** |
| Secrets on disk | Bitwarden ciphertext only (cache and queue) |
| Secrets on the bus | DH-AES sessions when clients ask (libsecret and secretstorage do) |
| Cross-app reads | Item ACL plus a fail-closed confirmation |
| Server-controlled input | KDF bounds; type-2 MAC verified before decrypt; error text clipped to 200 characters |

### Review findings and fixes

| Severity | Finding | Fix |
|---|---|---|
| Medium | `Collection.Delete` skipped ACL checks for the items it deletes | Authorize every item before deleting |
| Medium | "Always allow" was mapped from an ambiguous pinentry result (fail-open) | Two-step confirmation; only an explicit OK grants anything |
| Medium (supply chain) | `cargo audit`: RUSTSEC-2023-0071 in `rsa`, a dev-dependency | Removed; it was no longer used |

### Static checks

- `cargo clippy --all-targets` is clean at the default level. Pedantic
  findings were reviewed, and the numeric casts were changed to `try_from`.
- `cargo audit` reports no vulnerabilities (274 crates) after removing
  `rsa`.

## 11. Verification

| Suite | Where | Result |
|---|---|---|
| Unit tests (`cargo test`) | macOS; Linux glibc aarch64; Linux musl aarch64 and x86_64 | **19 passed** each (+1 ignored perf test) |
| End-to-end (`tests/e2e`, pytest under `dbus-run-session`) | Debian trixie container, arm64 | **18 passed** |

The unit tests cover:

- **Crypto**: known-answer vectors from an independent Python
  implementation (`tests/fixtures/gen_vectors.py`). They check PBKDF2
  (600k), Argon2id (64 MiB) and the stretched keys, the protected user key,
  and EncStrings byte-for-byte for a fixed IV.
- Tamper and type rejection, and KDF bounds.
- Item mapping: text and binary round trips, large secrets in notes,
  oversize refused, foreign fields, URIs, unknown properties and history
  kept, per-item keys, items made by other clients.
- The DH handshake played from the client side, and degenerate keys.
- The locked index across restarts (and that it contains no plain
  attribute values), snapshot diffs, the session collection, pinentry
  escaping, URL rules, key normalisation, out-of-date detection.

The end-to-end tests use real clients against a real `bwss` on a private
session bus:

- **Memory backend**:
  - CLI unlock, lock, status and wrong password;
  - `secret-tool` store, lookup, search and clear;
  - store while locked: two GETPINs, a SETERROR, then success;
  - cancelled prompt;
  - secretstorage DH session with a binary secret and content type,
    relabel, new attributes, new secret, delete;
  - `replace`, locked search plus prompt unlock, dismissed unlock;
  - ACL deny, once, deny, always, then remembered, with the creator never
    asked;
  - collections create, use and delete;
  - GetSecrets;
  - garbage input (bad DH key, unknown algorithm, bogus session).
- **Bitwarden backend against Vaultwarden 1.37.4**, checked by an
  independent Python Bitwarden client (`tests/e2e/bwclient.py`, sharing no
  code with bwss):
  - `secret-tool store` lands as a login with `bwss:*` fields, and a rotation
    keeps the old value in the history;
  - items made by the other client appear after `bwss sync`, remote edits
    are picked up, and `clear` trashes the item;
  - after a daemon restart, `secret-tool lookup` finds the locked item
    through the index and unlocks through the prompt;
  - offline: unlock from the cache, read, queue a write; after reconnecting,
    the queue is flushed and the independent client sees the item;
  - collections become sub-folders;
  - a wrong master password is reported.

Bugs the end-to-end suite found, all fixed:

1. `Item.GetSecret` returned four out-arguments instead of one
   `(oayays)` struct. zbus spreads a returned struct, so it is now wrapped
   in a 1-tuple.
2. A dismissed prompt sent a string result, and libsecret hung.
3. The offline cache was only written at unlock, so items created later
   were missing offline.
4. Two harness bugs: the fake pinentry was not executable, and its log
   lines broke at newlines.

## 12. Portability

| Target | Build | Unit tests | End-to-end |
|---|---|---|---|
| macOS aarch64 (development) | ✓ | 19 ✓ | — (no Secret Service on macOS) |
| Linux glibc aarch64 (Debian 13) | ✓ | 19 ✓ | 18 ✓ |
| Linux musl aarch64 (Alpine), static 13 MB binary | ✓ | 19 ✓ | not run |
| Linux musl x86_64 (Alpine, emulated), static-pie 14 MB binary | ✓ | 19 ✓ | not run |

The code avoids platform specifics except for Linux `/proc`, which it uses
for ACL identities; elsewhere the identity falls back to "unknown
application". The daemon also compiles on macOS, which helped development,
but the Secret Service is a Linux/BSD API.

## 13. Performance

`cargo test --release perf -- --ignored --nocapture`, on the development
Mac (Apple Silicon):

| Operation | Budget | Measured |
|---|---|---|
| PBKDF2-SHA256, 600,000 iterations | 3,000 ms | 48 ms |
| Argon2id 64 MiB, t=3, p=4 | 5,000 ms | 80 ms |
| Encode 10,000 items | 5,000 ms | 114 ms |
| Decode 10,000 items | 5,000 ms | 94 ms |
| Load 10,000 items into the keyring | 1,000 ms | 8 ms |
| Search 10,000 items | 50 ms | 0.4 ms |
| 1,000 searches | 2,000 ms | 145 ms |
| Open a DH session | 100 ms | 0.7 ms |
| Encrypt 10,000 secrets for the bus | 1,000 ms | 3 ms |

The release build of the whole end-to-end suite runs in about 7.5 s,
including 600k-iteration PBKDF2 unlocks against Vaultwarden.

## 14. Limitations and future work

- **No PAM module yet.** Unlock happens on the first request, or through
  `bwss unlock` from a login hook.
- **Not implemented**: `ChangeLock` (the lock is the Bitwarden master
  password) and aliases other than `default`.
- **Unsupported item formats**: organization items and COSE (type 7) items
  are not read, even with `whole_vault`; neither are cards, identities and
  SSH keys.
- **No Flatpak portal**: `org.freedesktop.impl.portal.Secret` is not
  implemented.
- **ACL identity**: executable paths only. Interpreters and scripts are not
  told apart.
- **No real-time updates**: changes are polled (SignalR is not used).
- **End-to-end coverage**: the tests run on arm64 Debian. Other
  distributions and x86_64 are covered by the build and unit tests; see
  the portability results.
