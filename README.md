<div align="center">

# 🔐 bwss

**Your Linux keyring, in your Bitwarden vault.**

A drop-in replacement for gnome-keyring's Secret Service that keeps every
secret in Bitwarden, so it follows you to every machine like iCloud Keychain
does on a Mac.

`org.freedesktop.secrets` · Rust · Bitwarden & Vaultwarden · offline-first · per-app access control

</div>

---

Your browser, IDE, mail client, Wi-Fi manager and `git` keep their passwords
in the desktop keyring. On Linux that keyring is a file on one machine: set up
a new laptop and you start over, and lose the disk and the secrets go with it.

**bwss** implements the standard
[freedesktop Secret Service API](https://specifications.freedesktop.org/secret-service/),
so every app that already talks to gnome-keyring or KWallet works unchanged.
The storage behind it is your Bitwarden vault: any login or secure note you
mark with a `bwss:id` field becomes a keyring item.

```console
$ secret-tool store --label="GitHub token" service github user me
Password: ••••••••          # first use: a pinentry dialog asks for your Bitwarden master password
$ secret-tool lookup service github
ghp_8x7…
```

…and *GitHub token* now shows up in Bitwarden on your phone, and in the
keyring of every other machine running bwss.

## 🏷️ Marking items for bwss

An item joins the keyring when it carries a custom field named `bwss:id`.
The value can be any non-empty text. Add the field to a personal login or
secure note, in any folder, with any Bitwarden client.

- **Unmarked items stay private.** bwss reads only their field names. They
  are never decrypted further and never reach the bus.
- **Finding a hand-marked item.** Apps see derived attributes `bwss:id`,
  `bwss:name`, `bwss:username` and `bwss:uri`, so you can look an item up
  with `secret-tool lookup bwss:name GitHub` even though no app created it:

  ```console
  $ secret-tool lookup bwss:name GitHub
  ghp_8x7…
  ```

- **Where the secret is read from.** The first of these that exists wins:
  1. a custom field `bwss:password` (even when empty);
  2. the item's notes, when the field `bwss:location=notes` is set;
  3. the login password (login) or the note text (secure note).
- **Where a write goes.** Back to where the secret was read. Changing a login
  password keeps the old one in password history, like the official clients.
  Add a `bwss:password` field when you want an app-only value and leave the
  login password alone.
- **Binary secrets** never go into the user's login password or note text. bwss
  adds a hidden `bwss:password` field with `bwss:encoding=base64` instead.
- **New items** that apps create are personal secure notes in the `folder`
  from your config (default `secret-service`), with the secret in
  `bwss:password`. A very large secret uses the new note's own notes.
- **Deleting from an app** removes all `bwss:*` fields. The item goes to the
  Bitwarden trash only when nothing of yours is left. Content from other
  tools counts as yours: an item with `obsidian:*` fields, a login password
  or your own notes is kept, just no longer marked.
- **Collections** come from the `bwss:collection` field, not from folders.
  `login` (alias `default`) always exists. The list of collections apps
  created is kept in a secure note marked `bwss:id=_collections`.

bwss follows the dybw data model 1.1, shared with the Obsidian plugin
keychain-bitwarden.

**Coming from the old folder-based bwss?** There is no migration: start over.
Items it created carry `bwss:id`, so they show up as marked items, but its
folder-based collections are not recognised, and an old config with a key
this version no longer has stops the daemon at start (remove that key). The old cache and locked index are rebuilt, and an old
offline queue is renamed `queue.json.legacy` and never replayed, so flush
offline writes before upgrading. See
[`docs/design.md`](docs/design.md) section 14.

## ✨ Features

- **Works with your existing apps**: anything that speaks Secret Service.
  That includes libsecret (`secret-tool`, GNOME apps), Chromium and Electron
  apps such as VS Code, NetworkManager, Python `keyring`/`secretstorage`,
  and `oo7`.
- **Synced everywhere.** Items are ordinary Bitwarden logins and secure
  notes: visible and editable in every Bitwarden client, and shared by every
  bwss instance on the same account.
- **Unlock once.** The first app that needs a secret pops up a pinentry
  dialog. Scripts and login hooks can use `bwss unlock --password-stdin`.
- **Per-app access control, like the macOS Keychain.** The app that created
  an item can use it freely. Any other executable triggers
  *Allow / Deny*, then *Always allow / Only this time*. The check fails
  closed: only an explicit "Allow" grants access.
- **Offline-first.** The last sync is cached, still encrypted. The keyring
  unlocks and reads with no network; writes are queued in order and
  replayed when you are back online.
- **Locked, but findable.** A locked keyring still answers searches from a
  salted attribute index, so apps trigger the unlock prompt instead of
  failing silently after a reboot.
- **Your Bitwarden data stays intact.** Editing an item keeps its username,
  URIs, custom fields, attachments and history, and a replaced login
  password goes into password history.
- **Small and self-contained**: one binary, and the musl build is fully
  static. It talks to Bitwarden directly, with no `bw` CLI or
  Node.js.

## 🧭 How it compares

| | gnome-keyring | KeePassXC (Secret Service) | **bwss** |
|---|---|---|---|
| Where secrets live | local keyring file | local KDBX file | **your Bitwarden vault** |
| Multi-device sync | — | sync the file yourself | **built in (Bitwarden)** |
| Phone / browser access | — | via third-party apps | **every Bitwarden client** |
| Works offline | ✓ | ✓ | ✓ (cached, queued writes) |
| Ask before another app reads a secret | — | ✓ | ✓ |
| Self-hostable server | — | — | ✓ (Vaultwarden) |

## 🏗️ How it works

```mermaid
flowchart LR
  A["apps<br/>(secret-tool, browsers,<br/>VS Code, NetworkManager…)"] -- "D-Bus · org.freedesktop.secrets" --> B[bwss]
  B -- "pinentry" --> U((you))
  B -- "HTTPS · end-to-end encrypted" --> V[(Bitwarden /<br/>Vaultwarden)]
  B -. "encrypted cache<br/>+ offline queue" .-> C[(~/.cache/bwss)]
```

| Secret Service | Bitwarden |
|---|---|
| default collection (`login`, alias `default`) | marked items without `bwss:collection` |
| collection "Work" | items with `bwss:collection=work` |
| item label | item name |
| secret | `bwss:password` field, notes, login password or note text (base64 for binary data) |
| attributes (`service=github`, …) | custom fields `bwss:attr:service`, … |
| `session` collection | memory only, never stored |

- **Encryption**: bwss implements Bitwarden's client-side crypto itself:
  PBKDF2 or Argon2id, HKDF, and AES-256-CBC with HMAC.
- **What goes over the network**: Bitwarden ciphertext only. Your master
  password never leaves the machine.
- **API key**: it only *authenticates*. Decrypting still needs your master
  password.

## 🚀 Quick start

**1. Build and install**

```sh
git clone <this repository> && cd bwss
cargo install --path .            # puts bwss in ~/.cargo/bin
```

**2. Connect your account.** Get a personal API key from the Bitwarden web
vault: *Settings → Security → Keys → View API key*.

```sh
bwss login --email you@example.com --client-id user.xxxxxxxx   # asks for client_secret
# Self-hosted? add: --server https://vault.example.org
```

This writes `~/.config/bwss/config.toml` and `~/.config/bwss/credentials.toml`,
both with mode `0600`. See
[`contrib/config.example.toml`](contrib/config.example.toml) for the options
(folder for new items, pinentry program, access control, idle lock, sync interval).

**3. Take over the keyring.** Stop gnome-keyring's secrets component (or
KWallet's or KeePassXC's integration) first, then:

```sh
install -Dm644 contrib/bwss.service ~/.config/systemd/user/bwss.service
install -Dm644 contrib/org.freedesktop.secrets.service \
  ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
systemctl --user daemon-reload
systemctl --user enable --now bwss.service
```

**4. Use it.** Your apps already know how; the CLI covers the rest:

```sh
bwss status      # locked/unlocked · item count · queued offline changes
bwss unlock      # pinentry, or: bwss unlock --password-stdin
bwss lock
bwss sync        # pull changes now (otherwise every 5 minutes)
```

## 🔒 Security

- The master password is used only locally, to derive keys. Key material is
  zeroized when the keyring locks.
- HTTPS is required (plain http is accepted only for `localhost`), and
  redirects are not followed, so the API key cannot be bounced to another
  host.
- Only Bitwarden's authenticated encryption (EncString type 2) is accepted.
  Server-supplied KDF parameters are range-checked to stop downgrades and
  resource exhaustion.
- Secrets cross D-Bus encrypted whenever the client asks for it
  (`dh-ietf1024-sha256-aes128-cbc-pkcs7`, the libsecret default).
- On disk there is only Bitwarden ciphertext, plus the locked index. The
  index holds salted attribute hashes, never secrets; this is the same
  trade-off gnome-keyring makes.

What bwss is **not**: a sandbox. Per-app control identifies apps by
executable path (`/proc/<pid>/exe`), so all Python scripts share
`/usr/bin/python3`. Any process running as your user can still inspect
other processes. It stops quiet cross-app reads, not a determined local
attacker.

## 🧪 Status

bwss is **young**: tested, but not yet battle-tested. Please try it before
you trust it with secrets you cannot recover from Bitwarden itself.

| Check | Result |
|---|---|
| Unit tests (crypto known-answer vectors, mapping, write-back, sessions, keyring) | 98 pass, 1 ignored (perf) |
| End-to-end against Vaultwarden 1.37.4 | 26 pass (14 Bitwarden, 12 Secret Service) |
| `cargo fmt --check`, `cargo clippy --locked --all-targets` | clean |

**Not tested yet**: bitwarden.com itself (all server tests used
Vaultwarden), desktop apps such as Chromium and VS Code under a real
session, and end-to-end tests on x86_64.

**Roadmap**:

- a PAM module for unlock-at-login;
- the Flatpak secret portal;
- `bwss import`, to tag existing Bitwarden logins from any folder;
- organization collections;
- push updates instead of polling.

## 🛠️ Development

```sh
cargo test                                            # unit tests
cargo test --release perf -- --ignored --nocapture    # performance budgets

# End-to-end on Linux: dbus, secret-tool, python-secretstorage
docker build -t bwss-e2e tests/e2e
docker run --rm -v "$PWD":/src -v bwss-target:/target -v bwss-cargo:/usr/local/cargo/registry bwss-e2e

# …and against a throwaway Vaultwarden (the test container joins its network)
docker run -d --rm --name bw-it -e SIGNUPS_ALLOWED=true -e SIGNUPS_VERIFY=false \
  -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true vaultwarden/server:latest
docker run --rm --network container:bw-it -e BW_E2E_URL=http://127.0.0.1:80 \
  -v "$PWD":/src -v bwss-target:/target -v bwss-cargo:/usr/local/cargo/registry bwss-e2e
```

CI runs the same checks on both forges:

- **GitHub** (`.github/workflows/`): fmt and clippy, unit tests on x86_64,
  aarch64 and macOS, `cargo audit`, and the end-to-end suite against a
  Vaultwarden service container. It also builds static musl binaries for
  x86_64 and aarch64. Pushing a `v*` tag creates a release with those
  binaries and their checksums. Actions are pinned to commit SHAs, and the
  release path uses no caches.
- **GitLab** (`.gitlab-ci.yml`): the same jobs. Releases are published to
  the Generic Package Registry and linked from the release. aarch64 builds
  need an arm64 runner (`ARM64_RUNNER_TAG`, which defaults to GitLab.com's
  `saas-linux-small-arm64`).

The full design is in [`docs/design.md`](docs/design.md): the item model, collections, writing and deletion,
locking, sessions, prompts, access control, the offline queue, the security
review and the test matrix. The original plan is in
[`docs/plan.md`](docs/plan.md).

---

<sub>bwss is an independent project. It is not affiliated with or endorsed by
Bitwarden, Inc. "Bitwarden" is a trademark of Bitwarden, Inc.</sub>
