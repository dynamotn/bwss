# bwss reference

Commands, configuration, files, and the exact rules that turn Bitwarden
items into keyring items. The [README](../README.md) covers setup; the full
design is in [design.md](design.md).

## Commands

| Command | What it does |
|---|---|
| `bwss daemon [--replace]` | Run the Secret Service (the systemd unit does this). `--replace` takes over `org.freedesktop.secrets` from another provider, when that provider allows it. |
| `bwss status` | Locked or unlocked, item count, queued offline changes, and anything that needs your attention. |
| `bwss unlock` | Unlock through the daemon's own pinentry; no password crosses the bus. |
| `bwss unlock --password-stdin` | For scripts: send the password read from the first line of stdin (see [security](security.md#unlocking)). |
| `bwss lock` | Lock the keyring and forget the keys. |
| `bwss sync` | Pull changes from Bitwarden now. |
| `bwss sync --accept-rollback` | When `bwss status` lists items the server sent older than the copy on this device, take the server's versions in this one sync (for example after restoring the server from a backup). |
| `bwss answer <id> login\|separate\|cancel` | Answer the password history question a queued change waits on, as `bwss status` lists it: write to the login password, keep the app's value in its own field, or drop the value change. The daemon confirms `login` and `separate` in its pinentry first, then syncs. |
| `bwss login --client-id <id> [--client-secret-stdin]` | Save the API key of the profile bwss serves, bound to its server. |
| `bwss acl off` / `on` | Turn per-app access control off or on, on this device only. Turning it off asks on the terminal first. Restart the daemon to apply. |
| `bwss derive on` / `off` | Show the item name, username and URI of marked items to apps and in the locked index on this device, or hide them (the default). Turning it on asks on the terminal first. `bwss index derived` is a deprecated alias. |
| `bwss config migrate` | Move an old `~/.config/bwss/config.toml` into the shared dybw file. |
| `bwss kdf accept` | After an unlock refused a KDF weaker than the one this device pinned: show it in the pinentry and, once you confirm it (check it in the web vault first), accept it on this device. |
| `bwss security accept <version>` | After an unlock refused an older account security state: accept that version on this device, for a profile moved to another server or account. |

Set `BWSS_LOG` (for example `BWSS_LOG=debug`) to change the daemon's log
level; the default is `info`.

## Configuration

bwss shares one file with the other dybw tools:
`$XDG_CONFIG_HOME/dybw/config.toml`, usually `~/.config/dybw/config.toml`.
[`contrib/config.example.toml`](../contrib/config.example.toml) documents
every key.

**Top level** (shared by every profile; a profile may override them):

| Key | Default | Meaning |
|---|---|---|
| `default` | | The profile to serve, unless `[bwss] profile` says otherwise. |
| `lock_timeout_minutes` | `60` | Lock after this long without use; `0` turns the idle lock off. |
| `sync_interval_seconds` | `300` | Pull changes this often (values under 30 count as 30). |
| `pinentry` | `pinentry` | The program that asks for the master password. It must not be writable by you, nor any directory above it. |
| `auth` | `api-key` | bwss supports only `api-key`. |

**`[profiles.<name>]`**: `server_url`, `email`, and overrides of `auth`,
`lock_timeout_minutes`, `sync_interval_seconds` and `pinentry`.

**`[bwss]`**:

| Key | Default | Meaning |
|---|---|---|
| `profile` | the top-level `default` | The profile bwss serves. |
| `folder` | `secret-service` | The folder where items created by apps go. |
| `backend` | `bitwarden` | `memory` keeps everything in the daemon, for tests and demos (with `memory_password`). |
| `notifications` | `true` | While unlocked, follow the server's notifications hub and pull about two seconds after a change made elsewhere. The sync timer keeps running as the fallback. |

An unknown key at the top level, in the served profile or in `[bwss]` stops
bwss, so typos fail loudly. Other tools' sections are ignored. Nothing in
the file can switch a protection off: `acl` is refused, and access control
and derived attributes are device state, set with `bwss acl` and
`bwss derive`.

## Files

| Path | What |
|---|---|
| `~/.config/dybw/config.toml` | The configuration. |
| `~/.local/state/dybw/profiles/<profile>/credentials` | The API key (mode `0600`). |
| `~/.local/state/dybw/profiles/<profile>/devices/bwss` | This device's id. |
| `~/.local/state/dybw/tools/bwss/` | Device decisions: `acl-off`, `acl-confirmed`, `derive-on`. |
| `~/.local/state/bwss/queue.json` | The offline write queue, sealed. |
| `~/.cache/bwss/` | The encrypted offline copy of the vault and `locked-index.json`. |

All of them follow `XDG_CONFIG_HOME`, `XDG_STATE_HOME` and `XDG_CACHE_HOME`
when set.

## How items map

**An item joins the keyring when it carries a custom field named `bwss:id`.**
Add it to a personal login or secure note, in any folder, with any
Bitwarden client; the value can be any non-empty text. Unmarked items stay
private: bwss reads only their field names and never puts them on the bus.

| Secret Service | Bitwarden |
|---|---|
| default collection (`login`, alias `default`) | marked items without `bwss:collection` |
| collection "Work" | items with `bwss:collection=work` |
| item label | `bwss:label`, falling back to the `bwss:id` (the item name with `bwss derive on`) |
| secret | see *Reading the secret* below |
| attributes (`service=github`, ...) | custom fields `bwss:attr:service`, ... |
| `session` collection | memory only, never stored |

**Finding an item.** Apps find a marked item by its `bwss:attr:*` fields, or
by `bwss:id` (`secret-tool lookup bwss:id github`). The item name, username
and first URI (`bwss:name`, `bwss:username`, `bwss:uri`) are hidden on the
bus and in the locked index unless you run `bwss derive on` on that device.
`bwss status` lists the marked items that have no `bwss:attr:*` field.

**Reading the secret.** The first of these that exists wins:

1. a custom field `bwss:password` (even when empty);
2. the item's notes, when the field `bwss:location=notes` is set;
3. the login password (logins) or the note text (secure notes).

**Writing the secret** goes back where it was read. Changing a login
password keeps the old one in password history, as the official clients do.
Add a `bwss:password` field when you want an app-only value and leave the
login password alone. Binary secrets never go into your login password or
note text: bwss adds a hidden `bwss:password` with `bwss:encoding=base64`
instead.

**Your password history is protected.** The first time an app writes to a
login password from this device, and whenever a write would push out of a
full history a password this device did not write, the pinentry asks first:
write to the login, keep the app's value separate (in a hidden
`bwss:password`), or cancel. A queued change that meets this question waits;
`bwss status` lists it and `bwss answer` answers it.

**New items** that apps create are personal secure notes in the `folder`
from your config, named after the label, with the secret in
`bwss:password`. A very large secret moves into the note's own text.

**Deleting from an app** removes every `bwss:*` field. The item goes to the
Bitwarden trash only when nothing of yours is left; a login password, your
own notes or another tool's fields (such as `obsidian:*`) keep it, just no
longer marked.

**Editing keeps your data.** bwss changes only its own fields and the value
source it read; usernames, URIs, other custom fields, attachments and
history pass through unchanged.

**Collections** come from the `bwss:collection` field, not from folders.
`login` (alias `default`) always exists; the collections apps created are
listed in a secure note marked `bwss:id=_collections`.

bwss follows the dybw data model 1.6, shared with the Obsidian plugin
keychain-bitwarden. See [design.md](design.md) §3 to §5 for every rule.

## Upgrading from the folder-based bwss

bwss stops on a `~/.config/bwss/config.toml` and asks you to run
`bwss config migrate`. That moves the account, settings, API key and device
id into the shared file and state directory, and renames the old files to
`*.migrated`. It refuses an old config with a key this version no longer has
(remove that key, such as `whole_vault`, first).

Vault items are not migrated: items the old version created carry `bwss:id`
and show up as marked items, but its folder-based collections are not
recognised. The cache and locked index are rebuilt, and an old offline queue
is renamed `queue.json.legacy` and never replayed, so flush offline writes
before upgrading. See [design.md](design.md) §14.
