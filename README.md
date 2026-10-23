# bwss — a Secret Service keyring backed by Bitwarden

`bwss` implements the freedesktop
[Secret Service API](https://specifications.freedesktop.org/secret-service/)
(`org.freedesktop.secrets`) on Linux, the same API gnome-keyring and KWallet
provide. Secrets are stored in a folder of your Bitwarden vault. It aims to
behave like the macOS Keychain:

- **One standard API for every app**: libsecret (`secret-tool`, GNOME
  apps), Chromium and Electron apps (VS Code), NetworkManager,
  python-keyring and `secretstorage`, `oo7`.
- **Unlock once.** The first app that needs a secret brings up a pinentry
  dialog asking for the Bitwarden master password. Scripts and login hooks
  can use `bwss unlock` instead.
- **Per-app access control.** The app that created an item can use it.
  When any other executable asks, you get *Allow once / Always allow / Deny*.
- **Every device stays in sync.** Items are Bitwarden logins: they show up,
  masked, in every Bitwarden client, and every machine running bwss with the
  same account sees the same keyring.
- **Works offline.** The last sync is cached (still encrypted), so the
  keyring unlocks and reads without a network. Writes are queued and
  replayed later.

## How data is stored

| Secret Service | Bitwarden |
|---|---|
| default collection (`login`, alias `default`) | folder `secret-service` |
| collection "Work" | folder `secret-service/Work` |
| item label | item name |
| secret | login password (or notes for secrets over Bitwarden's password limit) |
| attributes | custom fields `ss:attr:<name>` |
| stable id, content type, ACL, creation time | custom fields `ss:id`, `ss:content-type`, `ss:acl`, `ss:created` |
| `session` collection | memory only, never stored |

- Editing an item keeps everything bwss does not own: username, URIs, other
  fields, attachments, and the password history, where the old value is
  added on every change.
- Deleting an item moves it to the Bitwarden trash.
- Logins and secure notes you create in the folder with any Bitwarden client
  appear in the keyring too.

## Install and set up

```sh
cargo install --path .                    # or: cargo build --release
bwss login --email you@example.com --client-id user.xxxx   # asks for the client_secret
# API key: Bitwarden web vault → Settings → Security → Keys → View API key
```

That writes two files:

- `~/.config/bwss/config.toml`; see `contrib/config.example.toml` for the
  options.
- `~/.config/bwss/credentials.toml`, mode 0600.

Then stop the existing provider and start bwss:

```sh
# Stop gnome-keyring's secrets component, KWallet's, or KeePassXC's integration first.
install -Dm644 contrib/bwss.service ~/.config/systemd/user/bwss.service
install -Dm644 contrib/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
systemctl --user daemon-reload
systemctl --user enable --now bwss.service
```

Day to day:

```sh
secret-tool store --label="GitHub token" service github user me   # unlock prompt if locked
secret-tool lookup service github
bwss status       # locked / unlocked, item count, queued offline changes
bwss lock
bwss unlock       # pinentry; or: bwss unlock --password-stdin
bwss sync         # pull changes from Bitwarden now (it also does this every 5 minutes)
```

## Security notes

- **Master password**: it is only used locally, to derive the key. The
  API key only authenticates; it cannot decrypt anything.
- **HTTP client**: HTTPS is required (plain http only to localhost), and
  redirects are not followed, so the API key cannot be bounced to another
  host.
- **Ciphertext**: only Bitwarden's authenticated encryption (EncString type
  2) is accepted. KDF parameters from the server are range-checked.
- **On the bus**, secrets travel encrypted when the client asks for it
  (`dh-ietf1024-sha256-aes128-cbc-pkcs7`, which libsecret and secretstorage
  use by default).
- **While locked**, decrypted secrets are dropped. A small *locked index* of
  salted attribute hashes stays on disk (`~/.cache/bwss/locked-index.json`)
  so apps can find what they need to unlock. Like gnome-keyring, this
  reveals that items exist and lets someone holding the file test guesses of
  attribute values. It never reveals secrets.
- **The ACL is a speed bump, not a sandbox.** It identifies apps by
  executable path through `/proc/<pid>/exe`. Every process of your user can
  still ptrace other processes. Interpreters share one identity:
  `/usr/bin/python3` covers every Python script.
- **Offline cache**: `~/.cache/bwss/sync.json` holds Bitwarden ciphertext,
  the same data the server stores.

## Development

```sh
cargo test                                  # unit tests (crypto vectors shared with the Obsidian plugin)
docker build -t bwss-e2e tests/e2e          # Linux: dbus, secret-tool, python-secretstorage
docker run --rm -v "$PWD":/src -v bwss-target:/target -v bwss-cargo:/usr/local/cargo/registry bwss-e2e

# Against Vaultwarden (shares its network namespace, so it is reachable on 127.0.0.1):
docker run -d --rm --name bw-secrets-it -e SIGNUPS_ALLOWED=true -e SIGNUPS_VERIFY=false \
  -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true vaultwarden/server:latest
docker run --rm --network container:bw-secrets-it -e BW_E2E_URL=http://127.0.0.1:80 \
  -v "$PWD":/src -v bwss-target:/target -v bwss-cargo:/usr/local/cargo/registry bwss-e2e
```

The design and the plan are in [`../docs/bwss-plan.md`](../docs/bwss-plan.md).
