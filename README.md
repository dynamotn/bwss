# bwss

**Your Linux keyring, stored in your Bitwarden vault.**

bwss is a drop-in `org.freedesktop.secrets` provider. Apps that use
libsecret, browsers, `secret-tool` and anything else that talks to
gnome-keyring or KWallet keep working unchanged, but their secrets land in
your Bitwarden or Vaultwarden vault and follow you to every machine.

It adds per-app access control, an encrypted offline copy and a write queue
for when the server is out of reach, and ships `pam_bwss`, a PAM module
that hands your login password over so the keyring can unlock at login.

```console
$ secret-tool store --label="GitHub token" service github user me
Password: ********
$ secret-tool lookup service github
ghp_8x7...
```

*GitHub token* is now a secure note in your vault, visible in every
Bitwarden client and in the keyring of every other machine running bwss.

## Features

- **Works with existing apps**: anything that speaks the
  [Secret Service API](https://specifications.freedesktop.org/secret-service/),
  such as libsecret and `secret-tool`, GNOME apps, Chromium and Electron
  apps, NetworkManager, Python `keyring` and `secretstorage`.
- **Synced everywhere**: items are ordinary Bitwarden logins and secure
  notes, shared by every Bitwarden client and every bwss on the account.
- **Opt-in per item**: only items carrying a `bwss:id` field join the
  keyring; the rest of your vault stays private.
- **Per-app access control**: the app that created an item uses it freely;
  any other app gets an *Allow / Deny* prompt, like the macOS Keychain.
- **Offline-first**: unlock and read from an encrypted copy without
  network; writes are queued in order and replayed when the server is back.
- **Locks itself**: on `bwss lock`, after an idle timeout, on sleep and
  when your screen locks.
- **Leaves your data intact**: editing an item keeps its usernames, URIs,
  other fields, attachments and password history.
- **Small and self-contained**: one static binary that talks to Bitwarden
  directly, with no `bw` CLI or Node.js.
- **Self-hosting friendly**: works with Vaultwarden.

## Quick start

### 1. Install

Prebuilt static binaries for x86_64 and aarch64 are published on the
[GitHub releases page](https://github.com/dynamotn/bwss/releases); the first
release candidate, v1.0.0-rc.1, is on its way.

```sh
ARCH=x86_64            # or aarch64
VERSION=v1.0.0-rc.1
BASE=https://github.com/dynamotn/bwss/releases/download/$VERSION
curl -LO "$BASE/bwss-$ARCH-linux-musl.tar.gz"
curl -LO "$BASE/bwss-$ARCH-linux-musl.tar.gz.sha256"
sha256sum -c "bwss-$ARCH-linux-musl.tar.gz.sha256"
tar -xzf "bwss-$ARCH-linux-musl.tar.gz"
install -Dm755 bwss ~/.local/bin/bwss
```

Or build from source with Rust 1.89 or newer. This puts `bwss` in
`~/.cargo/bin`:

```sh
git clone https://github.com/dynamotn/bwss.git && cd bwss
cargo install --locked --path .
```

### 2. Configure

bwss reads `~/.config/dybw/config.toml`, a file shared with the other dybw
tools. A minimal one:

```toml
default = "personal"
pinentry = "/usr/bin/pinentry-gnome3"   # or pinentry-qt, pinentry-gtk-2, ...

[profiles.personal]
server_url = "https://vault.bitwarden.com"   # or your Vaultwarden URL
email = "you@example.com"

[bwss]
profile = "personal"
```

The pinentry must be a program you cannot write to, such as one installed
by your package manager; otherwise the daemon refuses to start.
[`contrib/config.example.toml`](contrib/config.example.toml) shows every
key.

Then save a personal API key from the web vault (*Settings > Security >
Keys > View API key*). It only logs bwss in; decrypting still needs your
master password.

```sh
bwss login --client-id user.xxxxxxxx     # asks for the client_secret
```

### 3. Enable the user service

Free the bus name first if gnome-keyring or KWallet holds it (see
[Replace gnome-keyring or KWallet](#replace-gnome-keyring-or-kwallet)),
then install the systemd unit and the D-Bus activation file:

```sh
install -Dm644 contrib/bwss.service ~/.config/systemd/user/bwss.service
install -Dm644 contrib/org.freedesktop.secrets.service \
  ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
systemctl --user daemon-reload
systemctl --user enable --now bwss.service
```

The unit runs `~/.cargo/bin/bwss`. If you installed the prebuilt binary in
`~/.local/bin`, point it there before `daemon-reload`:

```sh
sed -i 's|%h/.cargo/bin/bwss|%h/.local/bin/bwss|' ~/.config/systemd/user/bwss.service
```

### 4. Unlock

```console
$ bwss unlock          # a pinentry dialog asks for your master password
unlocked
$ bwss status
unlocked, 0 item(s), ...
```

You can also skip this step: the first app that needs a secret brings up
the same dialog.

### 5. Try it

```sh
secret-tool store --label="bwss test" service bwss-test user me
secret-tool lookup service bwss-test
secret-tool clear service bwss-test
```

The item shows up in the `secret-service` folder of your vault until you
clear it.

## Replace gnome-keyring or KWallet

Only one program can own `org.freedesktop.secrets`. If another one has it,
`bwss daemon` stops with a message that names the owner. To see who it is:

```sh
busctl --user status org.freedesktop.secrets | grep -E '^(PID|Comm)='
```

Then turn that provider's Secret Service off and log out and back in:

- **gnome-keyring**: hide its secrets autostart entry. The D-Bus
  activation file you installed in `~/.local/share/dbus-1/services` takes
  precedence over the system one.

  ```sh
  cp /etc/xdg/autostart/gnome-keyring-secrets.desktop ~/.config/autostart/
  echo 'Hidden=true' >> ~/.config/autostart/gnome-keyring-secrets.desktop
  ```

- **KWallet** (Plasma 6): turn off its Secret Service API.

  ```sh
  kwriteconfig6 --file kwalletrc --group org.freedesktop.secrets --key apiEnabled false
  ```

- **KeePassXC**: *Settings > Secret Service Integration*, untick
  *Enable KeePassXC Freedesktop.org Secret Service integration*.

`bwss daemon --replace` takes the name over from a running provider that
allows it. bwss does not import the old keyring file: apps store their
secrets again as you use them.

## Store secrets from apps

Apps need no setup. Whatever they store becomes a personal secure note in
the `secret-service` folder (set `folder` under `[bwss]` to change it), with
the secret and the app's lookup attributes in custom fields:

| Field | Holds |
|---|---|
| `bwss:id` | The marker: an item is in the keyring only when it has this field. |
| `bwss:password` | The secret. |
| `bwss:attr:<name>` | One lookup attribute each, such as `bwss:attr:service = github`. |
| `bwss:label` | The label apps show; without it, the label is the `bwss:id`. |
| `bwss:acl` | The apps allowed without asking. |

**Use an item you already have.** Add a custom field `bwss:id` with any
non-empty value to a personal login or secure note, in any folder and with
any Bitwarden client. Add `bwss:attr:*` fields for the attributes your app
looks up, then sync:

```sh
# Login "GitHub" with the custom fields  bwss:id = github  and  bwss:attr:service = github
bwss sync
secret-tool lookup service github        # the login password
secret-tool lookup bwss:id github        # the same item, by its id
```

For a login, the secret is the login password; for a secure note, the note
text. Add a `bwss:password` field to give apps a value of their own and
leave the login password alone.

Writes go back where they were read, and a replaced login password goes
into password history. Before an app first overwrites a login password from
this device, the pinentry asks whether to write it to the login or keep it
separate. Deleting from an app removes the `bwss:*` fields and only trashes
the item when nothing else of yours is left on it.

All the mapping rules, including collections and binary secrets, are in
[docs/reference.md](docs/reference.md#how-items-map).

## Control which apps can read what

Every read, change or delete of a secret is checked against the item's
`bwss:acl` list. The app that created an item is on it. Any other app gets
a pinentry prompt, *Allow / Deny*, then *Always allow / Only this time*.
Only an explicit *Allow* grants access.

```console
$ python3 ~/bin/backup.py              # a script is an app of its own:
                                       # answer "Always allow" once and it is not asked again
$ python3 -c 'import keyring; ...'     # inline code cannot be identified:
                                       # asked every time, never offered "Always allow"
```

- Apps are identified by their executable, and scripts by interpreter and
  script path.
- *Always allow* is stored in the item and syncs, but every other device
  asks you once before it honours that grant.
- To work like gnome-keyring, with no prompts on this device:

  ```sh
  bwss acl off                          # asks on the terminal first
  systemctl --user restart bwss
  ```

Access control is a speed bump against quiet cross-app reads, not a
sandbox; see [docs/security.md](docs/security.md#per-app-access-control).

## Unlock at login with pam_bwss

`pam_bwss.so` reads the password your login already collected and leaves
it in your kernel keyring for 60 seconds, for the process that unlocks the
vault with it. It never prompts, logs, writes files or touches the
network, and it never changes the outcome of a login.

> **The consumer is not released yet.** The dybw agent's `login` protector,
> which picks the password up and unlocks, is still to come. Until then the
> entries expire unused and you unlock with `bwss unlock`.

Build it with a glibc toolchain (the static release cannot), and install it
into your distribution's module directory:

```sh
cargo build --locked --release -p pam_bwss
sudo install -o root -g root -m 644 target/release/libpam_bwss.so <moduledir>/pam_bwss.so
```

| Distribution | `<moduledir>` |
|---|---|
| Debian, Ubuntu | `/usr/lib/x86_64-linux-gnu/security` (`aarch64-linux-gnu` on arm64) |
| Arch | `/usr/lib/security` |
| Fedora | `/usr/lib64/security` |

bwss never edits `/etc/pam.d`; add the lines yourself, each `optional` and
**after** `pam_unix`. Keep a root shell open while you try a new stack.

- **Debian, Ubuntu**: save a profile as `/usr/share/pam-configs/bwss` and
  run `sudo pam-auth-update`. The profile sets
  `Session-Interactive-Only: yes`, so cron jobs and other non-interactive
  sessions never run the module.
- **Arch, Fedora and others**: add to `/etc/pam.d/login`, your display
  manager's file (`gdm-password`, `sddm`, `lightdm`) and `/etc/pam.d/passwd`:

  ```
  auth      optional  pam_bwss.so
  session   optional  pam_bwss.so
  password  optional  pam_bwss.so
  ```

The full profile, the keyring entries and the caveats are in
[docs/pam_bwss.md](docs/pam_bwss.md).

## Work offline

Nothing to configure. On every unlock and sync, bwss keeps the vault's
ciphertext in `~/.cache/bwss`. When the server cannot be reached
(connection errors, HTTP 429 or 5xx):

- **unlock and reads** use that copy, with the same password check;
- **writes** apply to the keyring at once and wait, sealed, in
  `~/.local/state/bwss/queue.json`;
- **the queue is replayed in order** at the next sync that reaches the
  server, every `sync_interval_seconds` (default 300) or on `bwss sync`.

`bwss status` shows how many changes are queued. A change that needs your
answer (such as overwriting a login password) waits until you run
`bwss answer`.

While online and unlocked, bwss also follows the server's notifications and
pulls about two seconds after a change made on another device.

## How it works

```
  secret-tool, browsers, VS Code, NetworkManager, Python keyring, ...
                               |
                               |  D-Bus session bus: org.freedesktop.secrets
                               v
  +------------------------------------------------------------+
  | bwss daemon                                                |
  |   Secret Service objects, sessions, prompts, per-app ACL,  |
  |   idle / sleep / screen lock, locked index                 |
  +------------------------------------------------------------+
                               |
                               v
  +------------------------------------------------------------+
  | vault worker (one thread that owns the unlocked vault)     |
  |   offline copy, write queue, item mapping                  |
  +------------------------------------------------------------+
                               |
                               v
  +------------------------------------------------------------+
  | dybw-core: Bitwarden crypto, API client, sync              |
  +------------------------------------------------------------+
                               |
                               |  HTTPS, end-to-end encrypted
                               v
                    Bitwarden or Vaultwarden
```

The daemon answers Secret Service calls from an in-memory keyring built
from the marked items, and asks you through pinentry for the master
password and for access decisions. The vault worker holds the keys and
does every unlock, read and write through
[dybw-core](https://gitlab.com/dynamo-tools/dybw-core), the dybw tools'
shared Rust core, which implements Bitwarden's client-side crypto. Only
ciphertext leaves the machine.

## Security model

- **Your master password stays local.** It only derives keys; key material
  is wiped on lock. The API key only logs in.
- **Unlocked only while needed.** Idle timeout, sleep and screen lock all
  lock the keyring.
- **Fail-closed access control**, per app and per device.
- **Only ciphertext on disk**, plus a locked index of salted attribute
  hashes so apps can find locked items before the first unlock (the same
  trade-off gnome-keyring makes).
- **A server cannot quietly weaken the device**: a weaker KDF, an older
  account security state or rolled-back items are held until you accept
  them.
- **A synced config cannot switch protections off**, and the daemon
  refuses a pinentry you could replace. bwss never runs as root.
- **Not a sandbox**: a determined process running as your user can still
  pose as an allowed app.

The details are in [docs/security.md](docs/security.md), the full model in
[docs/design.md](docs/design.md) §11.

## Commands

| Command | What it does |
|---|---|
| `bwss status` | Locked or unlocked, item count, queued changes, anything that needs you. |
| `bwss unlock` / `bwss lock` | Unlock through pinentry, or lock and forget the keys. |
| `bwss sync` | Pull changes from Bitwarden now. |
| `bwss login --client-id <id>` | Save the API key of the profile bwss serves. |
| `bwss acl off` / `on` | Turn per-app access control off or on, on this device. |
| `bwss derive on` / `off` | Show or hide item names, usernames and URIs to apps, on this device. |
| `bwss daemon [--replace]` | Run the Secret Service (the systemd unit does this). |

`bwss answer`, `bwss kdf accept`, `bwss security accept`,
`bwss sync --accept-rollback`, `bwss config migrate`, every configuration
key and every file bwss writes are in
[docs/reference.md](docs/reference.md). Coming from the old folder-based
bwss? See [upgrading](docs/reference.md#upgrading-from-the-folder-based-bwss).

## Status

bwss is heading for its first release candidate, **v1.0.0-rc.1**. It is
tested, but not yet battle-tested: try it before you trust it with secrets
you cannot recover from Bitwarden itself.

- **Platform**: Linux only (D-Bus, systemd-logind, the kernel keyring).
- **Minimum Rust version**: 1.89.
- **Tested**: unit tests, dybw-core's conformance vectors, an end-to-end
  suite against Vaultwarden 1.37.4 with `secret-tool` and secretstorage,
  `pam_bwss` under `pamtester`, and a 100% line-coverage gate.
- **Not tested yet**: bitwarden.com itself (every server test uses
  Vaultwarden), desktop apps such as Chromium and VS Code in a real
  session, and screen locking under a real systemd-logind.
- **Not supported yet**: organization collections, the Flatpak secret
  portal, and unlocking at login (the `pam_bwss` consumer).

## License

The repository has no license file yet. dybw-core, which bwss builds on, is
MIT-licensed.

## Development

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets
cargo test --locked --workspace
```

The end-to-end suite runs in Docker against a throwaway Vaultwarden. See
[docs/development.md](docs/development.md) for the end-to-end and
`pam_bwss` suites, coverage and CI, and [docs/design.md](docs/design.md)
for the design.

---

bwss is an independent project. It is not affiliated with or endorsed by
Bitwarden, Inc. "Bitwarden" is a trademark of Bitwarden, Inc.
