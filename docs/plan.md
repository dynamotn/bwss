# bwss — plan

`bwss` is a freedesktop Secret Service daemon for Linux whose storage is a
folder of a Bitwarden vault. The goal is the day-to-day experience of the
macOS Keychain: apps store and find secrets through the standard API, the
keyring unlocks once per session, works offline, asks before handing one
app's secret to another app, and every device signed in to the same
Bitwarden account sees the same secrets.

## Goals

| Keychain behaviour | bwss equivalent |
|---|---|
| One system API every app uses | `org.freedesktop.secrets` on the session bus (libsecret, `secret-tool`, Chromium, VS Code, NetworkManager, python `secretstorage`/`keyring`, `oo7`) |
| Keychains and a default keychain | Collections, with the `default` alias; each collection is a Bitwarden folder `<root>/<collection>` |
| Unlock once at login | `Unlock` prompt asks for the master password through a pinentry program; `bwss unlock` for scripts and login hooks |
| Lock on demand / after idle | `Lock`, `LockService`, idle timeout; keys are zeroised on lock |
| Works offline | Encrypted on-disk cache of the last sync plus a queue of pending writes |
| Per-app access control ("Always allow") | Item ACL of executable paths; access from another app goes through a confirmation prompt |
| iCloud Keychain sync | Bitwarden sync: periodic pull plus write-through push; optimistic revision checks |

## Non-goals (for now)

- A PAM module for unlock-at-login (documented as follow-up; `bwss unlock`
  from a login hook covers the need meanwhile).
- `org.freedesktop.impl.portal.Secret` for Flatpak apps.
- Organization collections (RSA-wrapped organisation keys).
- `ChangeLock`, which has no meaning when the lock secret is the Bitwarden
  master password.

## Architecture

```
            session D-Bus
  apps ───► org.freedesktop.secrets ──► bwss daemon (tokio + zbus)
                                          │
              ┌───────────────────────────┼───────────────────────────┐
              ▼                           ▼                           ▼
        dbus/ (Service,           keyring/ (collections,        backend/ trait Backend
        Collection, Item,          items, search index,          ├─ MemoryBackend (tests)
        Session, Prompt;           locking, ACL decisions)       └─ BitwardenBackend
        plain + DH sessions)                                         ├─ bw/ crypto + API
                                                                     ├─ cache (encrypted sync
                                                                     │  snapshot, write queue)
                                                                     └─ sync loop
```

- **`bw` module**: the same Bitwarden client logic as the Obsidian plugin
  (PBKDF2/Argon2id, HKDF stretch, EncString type 2, per-item keys,
  `encryptedFor`, revision checks), on RustCrypto crates and reqwest with
  rustls.
- **Item mapping**: one Secure Note per Secret Service item.
  - `name` = label; `notes` = secret (UTF-8 text, or base64 when the bytes
    are not valid UTF-8).
  - Hidden fields: `ss:attr:<name>` per attribute, `ss:content-type`,
    `ss:encoding`, `ss:acl`, `ss:created`.
  - The folder carries the collection: `<root>` is the default collection,
    `<root>/<name>` is any other.
- **Search**: an in-memory index over decrypted attributes. It exists only
  while the keyring is unlocked. While locked, `SearchItems` reports matches
  as locked. This needs the attributes, which are encrypted, so a locked
  daemon returns no unlocked results. That is how the spec intends it.
- **Sessions**: `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7`
  (Oakley group 2, HKDF-SHA256 to a 128-bit AES key), as libsecret does.
- **Prompts**: `Prompt` objects run an external prompter. The default is
  `pinentry`, and it is configurable, for example `pinentry-gnome3` or a
  test helper. The prompter is used for the master password and for ACL
  confirmations ("Allow / Always allow / Deny").
- **ACL**: the caller's unique bus name is resolved to a PID through
  `GetConnectionUnixProcessID`, then to its executable through
  `/proc/<pid>/exe`. The executable that creates an item is recorded on it.
  Other executables trigger a confirmation prompt. This is a speed bump
  against casual cross-app reads, not a sandbox: any process of the same
  user can still read the daemon's memory. That is also true of
  gnome-keyring.
- **Offline**:
  - The sync snapshot is cached at `$XDG_CACHE_HOME/bwss/sync.json`. Its
    contents are still Bitwarden ciphertext, so the cache adds no exposure
    beyond what the server already stores.
  - Writes made while offline go to `queue.json` and are replayed on the
    next successful sync.
- **Config**: `$XDG_CONFIG_HOME/bwss/config.toml` holds the server URL,
  email, root folder, prompter, idle lock and ACL mode. The API key goes in
  a separate `credentials.toml`, written with mode 0600.

## Milestones

1. Workspace, `bw` module (crypto with known-answer vectors from the shared
   Python generator, API client, mapping).
2. D-Bus objects over `MemoryBackend`, including plain and DH sessions.
   Checked with `secret-tool` and python `secretstorage` inside a Linux
   container with its own session bus.
3. `BitwardenBackend` with cache, write queue and sync loop. Checked
   against Vaultwarden and cross-checked with the official Bitwarden CLI
   (what `secret-tool store` writes, `bw get` reads).
4. Prompts (unlock, ACL confirm), idle lock, `bwss` CLI (`daemon`,
   `unlock`, `lock`, `status`, `login`).
5. Portability (x86_64 and aarch64 Linux, glibc and musl), audit (cargo
   audit, clippy pedantic on the crypto/ACL code, review), performance
   (search over 10k items, `GetSecrets` latency, sync cost).
