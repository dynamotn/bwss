# bwss — redesign

This design follows the **dybw data model, version 1.1**
(`docs/data-model.md` in the dybw umbrella repository). That spec is
normative and wins over this document; this document adds the `bwss`
namespace's own rules (its fields are registered in dybw's
`docs/namespaces.md`). A change to a shared rule goes through a dybw ADR,
then the spec, then this document. Section references written "spec §n"
point into the data model.

This document describes bwss rebuilt from scratch around one idea: **a
vault item belongs to the keyring because the user marked it, not because of
where it sits.** It replaces the folder-based design now on the `legacy`
branch (a keyring folder plus `whole_vault`). It is written for whoever
builds it. Choices the author made without the user are marked
*(builder's call, revisable)*.

## 1. Intent

bwss gives Linux the macOS Keychain experience, with Bitwarden as the store.
Every Secret Service client (libsecret and `secret-tool`, Chromium and
Electron, NetworkManager, python `keyring` and `secretstorage`, `oo7`) reads
and writes secrets that live in the user's Bitwarden vault and follow them to
every device.

The redesign exists because the user wants the **whole vault** usable from
apps, without exposing the whole vault to every process on the session bus.
The model is borrowed from the obsidian-keychain-bitwarden plugin, which
solves the same problem for Obsidian:

- any item, in any folder or none, joins the keyring when it carries the
  custom field `bwss:id`;
- unmarked items are never decrypted beyond their field names;
- a changed secret is written back where it was read (spec §6.1), so a
  hand-marked login stays the one source for the browser, the official
  clients and apps; a new secret never lands in a password or notes the
  user owns;
- deleting from an app removes bwss's fields before it ever considers the
  Bitwarden trash.

### Goals

- Read and write marked items wherever they are, with the same rules for
  items bwss created and items the user marked by hand.
- Never lose user data: no app action may overwrite or trash anything the
  user put into an item.
- Keep every decision synced: ids, attributes, collections and "Always
  allow" rules travel inside the item to every device.
- Keep the keychain experience: one unlock, per-app confirmation, offline
  use, automatic sync.

### Non-goals

- Organization items and COSE (type 7) items in the first version (see §12
  for how they fit later).
- Cards, identities and SSH key items.
- A PAM module, the Flatpak secret portal, `ChangeLock`, and aliases other
  than `default`.
- Real-time sync through the notifications hub (polling stays).

### Anti-goals

These would make it a failure even if every test passed:

- Any unmarked item's name, username, URI, password or note reaching the
  bus, the cache in plain text, or a log.
- An app writing outside bwss's fields and the value source of the item
  it read, putting a new secret into a password or notes the user owns, or
  trashing an item that still holds something the user put there.
- Two devices disagreeing on which items exist or what their ids are.

## 2. Vocabulary

| Term | Meaning |
|---|---|
| Marker | A custom field named `bwss:id` with a non-empty value after trimming |
| Marked item | A personal login or secure note, not trashed, carrying a marker |
| bwss field | Any custom field whose name starts with `bwss:` |
| Value source | Where a marked item's secret was read from (§3.2, spec §5) |
| Foreign content | Everything in an item that is not a bwss field (see §5.4), including other tools' fields |
| Keyring folder | The folder new items are created in, `secret-service` by default |

## 3. Item model

### 3.1 Fields

| Field | Kind | Meaning |
|---|---|---|
| `bwss:id` | text | The marker and the item's stable id. bwss generates a UUID (32 hex digits) for items it creates; the user may type any value on items they mark. |
| `bwss:password` | hidden | Holds the secret when the field is present, even empty. New items keep their secret here. |
| `bwss:label` | text | The Secret Service label, when present. Label edits go here. |
| `bwss:attr:<name>` | text | One lookup attribute each. |
| `bwss:collection` | text | Collection id; absent means `login` (alias `default`). |
| `bwss:content-type` | text | Content type of the secret; absent means `text/plain`. |
| `bwss:encoding` | text | `base64` when the stored secret is base64 of non-UTF-8 bytes. Valid only with a source bwss owns: `bwss:password`, or the notes with `bwss:location=notes`. |
| `bwss:location` | text | `notes` when bwss itself moved an oversize secret into the notes (§5.2). |
| `bwss:acl` | hidden | Executables allowed without asking, one path per line. |
| `bwss:created` | text | Unix seconds when the item joined the keyring. |

Field names are matched exactly (case-sensitive). If an item carries the
same field twice, the first in field order counts, and a write changes only
that one (spec §3.1). Every field bwss does not own is kept on write: other
namespaces (`obsidian:*`, the reserved `dybw:*`), fields with no namespace,
and `bwss:` fields this version does not know, so newer versions can add
some.

### 3.2 Reading

For a marked item:

- **Label**: `bwss:label` if non-empty, else the item name.
- **Secret** (spec §5), from the first **present** source:
  1. the `bwss:password` field, when it exists, even with an empty value;
  2. the notes, when `bwss:location=notes`;
  3. `login.password` for a login, the notes for a secure note.

  Then base64-decode when `bwss:encoding=base64`. That is only valid with
  source 1 or 2: an item whose source is its login password or a secure
  note's own text and that carries `bwss:encoding=base64` is invalid. bwss
  skips it, logs it, lists it in `bwss status`, and never decodes the
  user's password (spec §5, ADR 0005). An empty result is a valid
  empty secret. bwss remembers the value source of each item; presence, not
  content, decides step 1, so the source does not change when a value
  becomes empty.
- **Attributes**: the `bwss:attr:*` fields, plus derived attributes that
  let a hand-marked item be found without typing attributes:
  `bwss:id`, `bwss:name` (item name), `bwss:username` and `bwss:uri` (first
  URI), each left out when empty. The `bwss:` prefix keeps ordinary app
  queries (`service=…`) from matching them by accident. A `bwss:attr:` field
  can not override a derived attribute. *(builder's call, revisable)*
- **Created / modified**: `bwss:created` (falling back to `creationDate`)
  and `revisionDate`.

### 3.3 Ids and object paths

- The id is the marker's value, trimmed. It is shared by every device
  because it is stored in the item, and Bitwarden syncs it like any field.
- The D-Bus path element is a **reversible** escape of the id: ASCII letters
  and digits stay, every other byte becomes `_xx` (lowercase hex), and `_`
  itself becomes `_5f`. Two different ids can therefore never share a path.
  UUIDs that bwss generates are unchanged by the escape.
- **Duplicate ids** (the usual cause is "Clone item" in a Bitwarden client,
  which copies the marker), spec §7: a personal item over an organization
  item (once those are read, §12), then the oldest `creationDate` (an item
  without one sorts last), then the lowest cipher id, wins on every
  device. The others are left out of
  the keyring, a warning is logged, and `bwss status` lists them so the
  user can fix them.

### 3.4 Unmarked items

To find markers, bwss decrypts the item key (when the item has one) and the
**names** of the custom fields, nothing else (spec §4). Values, item names,
notes, logins and URIs of unmarked items stay ciphertext in memory and on
disk.

An item bwss cannot inspect (a key it cannot unwrap, field names it cannot
decrypt, a newer ciphertext format, an organization item) is skipped with a
warning but is **not** treated as deleted: if it was in the keyring before
a refresh, it stays there as last read, without `ItemDeleted`, until it can
be read again or the keyring is locked. Marked items of another type
(card, identity, SSH key) are skipped and reported, as are items with a
`bwss:location` or `bwss:encoding` value this version does not know.

## 4. Collections

- Membership comes from `bwss:collection`, not from folders. Moving an item
  between folders in Bitwarden changes nothing for apps.
- Collection ids are lowercase. The field value is trimmed and lowercased;
  `default` means `login`. `session` is refused (the item stays in `login`,
  with a warning), because `session` is memory only.
- `login` (alias `default`) always exists. `session` always exists and is
  never stored.
- **Collection registry**: an app can create an empty collection, so
  collections need a record of their own. bwss keeps one secure note in the
  keyring folder, marked `bwss:id=_collections` and `bwss:kind=collections`,
  whose notes hold JSON: `{ "<id>": { "label": "...", "created": <secs> } }`.
  It is never exposed as an item. Unlike other items it is merged, never
  overwritten: several registry notes (two devices creating one while
  apart) are read as the union of their entries, and a write that hits an
  out-of-date rejection is redone on the fresh copy entry by entry. A
  deleted collection stays as `{ "deleted": true }` so a merge does not
  bring it back. *(builder's call, revisable)* The collections shown are the union of
  `login`, the registry and every collection id that marked items use.
  *(builder's call, revisable: the alternative is one sub-folder per
  collection, which is what `legacy` does and what this design moves away
  from.)*
- **Deleting a collection** applies the delete rule (§5.4) to every item in
  it, after authorizing each one, then removes its registry entry. `login`
  and `session` can not be deleted.

## 5. Writing

All writes go through one rule (spec §6.3, invariant 2): **bwss changes
only its own fields and the value source of the item it read.** Everything
else passes through unchanged.

### 5.1 Creating an item

- `CreateItem` makes a **secure note** (spec §6.2) in the keyring folder,
  personal (`organizationId: null`), named after the label, with empty
  notes and no login, and the fields `bwss:id` (new UUID), `bwss:password`
  (hidden, never the notes), `bwss:attr:*`, `bwss:collection` (unless
  `login`), `bwss:content-type` (unless `text/plain`), `bwss:acl` (the
  creator) and `bwss:created`.
- `replace=true` looks for an item in the same collection with exactly the
  same `bwss:attr:*` attributes (derived attributes do not count) and
  updates it instead.
- The keyring folder is created on first need, matched by exact name; with
  duplicate folder names the lowest id wins.

### 5.2 Changing the secret

- The new value goes back to the **value source** it was read from
  (spec §6.1):
  - `bwss:password`: the field is updated; the login password, the notes
    and the password history are left alone;
  - the notes (`bwss:location=notes`, or a secure note without
    `bwss:password`): the notes are updated;
  - `login.password`: the password is updated the way the official clients
    do it: the old password goes first into `passwordHistory` (at most 5
    entries) and `login.passwordRevisionDate` is set.

  So an app rotating the token of a hand-marked login updates that login,
  and the browser and the official clients see the new value. A user who
  wants an app-only value adds a `bwss:password` field to the item.
- **Binary values** (bytes that are not UTF-8) only go where bwss owns the
  storage (spec §6.1, ADR 0005):
  - when the source is `bwss:password` or bwss's notes, the value is
    stored as base64 with `bwss:encoding=base64`;
  - when the source is the login password or a secure note's own text,
    bwss instead adds a hidden `bwss:password` holding the base64, and
    `bwss:encoding=base64`, and leaves the password, its history and the
    notes untouched. That field is the source from then on (presence
    rule), so later writes, text or binary, go to it. The size rules below
    apply to it: a value too large for the field can only go to the notes
    when they are empty or already hold bwss's secret, which for a
    hand-marked note usually means the write fails.
  - Writing text removes `bwss:encoding`; text keeps going back where it
    was read.
- **Size** (spec §6.4): Bitwarden limits a field value to 5,000 encrypted
  characters, the login password to 5,000 and the notes to 10,000. A
  value that does not fit `login.password` fails. When a value whose
  source is `bwss:password` does not fit the field:
  - if the notes are empty or already hold bwss's secret
    (`bwss:location=notes`), it goes into the notes with
    `bwss:location=notes`, and `bwss:password` is removed;
  - otherwise the write fails with an error: bwss never overwrites notes
    the user wrote.
  - Above 10,000 the write fails.

### 5.3 Changing the label or attributes

- Label: written to `bwss:label`. The item name is left alone, except on
  creation.
- Attributes: the `bwss:attr:*` set is replaced as a whole. Derived
  attributes can not be set.

### 5.4 Deleting an item

1. Remove every bwss field. When `bwss:location=notes`, clear the notes too
   (they hold bwss's secret).
2. If what remains has **no foreign content**, move the item to the
   Bitwarden trash (restorable for 30 days). Otherwise save it, and it
   simply leaves the keyring.

Foreign content (spec §8.2) is any of: a non-empty login username,
password, TOTP or URI; non-empty notes; a custom field of **another
namespace** (for example `obsidian:id`) or with no namespace; an
attachment; a passkey (`login.fido2Credentials`); a non-empty password
history. The item name alone does not count. An item another tool also
marked is therefore never trashed by bwss.

The decision is made against the server's copy, never a stale one:
step 1 is saved first with `lastKnownRevisionDate`, and step 2 looks at
what the server returned (spec §8.2). If the save is rejected as out of
date, bwss refetches and starts over at step 1 (a user edit made elsewhere
in the meantime therefore keeps the item). A delete waiting in the offline
queue is stored as "delete item X", not as "trash X", and runs these same
steps when replayed.

An item bwss created and nobody edited therefore goes to the trash; a login
the user marked by hand keeps its password and only loses its bwss fields.
Removing all bwss fields, not just `bwss:password`, matters: otherwise the
item would stay in the keyring with its old login password and the app
would find it again after "deleting" it.

### 5.5 Passing items through

Every write (spec §6.3) starts from the cipher exactly as the server last
returned it and removes only response-only metadata (`id`, `revisionDate`,
`creationDate`, `deletedDate`, `object`, `edit`, `viewPassword`,
`permissions`, `collectionIds`, `attachments`, `organizationUseTotp`,
`data`). Unknown properties (newer item types, archive state), passkeys,
URIs, TOTP, the folder and other tools' fields survive. It keeps the item
key (`cipher.key`) and encrypts under it, always sends `passwordHistory`
back (the server replaces it with what it receives), and sends
`lastKnownRevisionDate` and `encryptedFor`.

### 5.6 Conflicts

When the server rejects a write as out of date (spec §6.5), bwss refetches
the item and re-applies **its own changes** (never a stale whole body) to
the fresh copy, then retries. Edits made elsewhere to parts bwss is not
changing are never clobbered. Then:

- if the **value source** changed on the server since bwss read it, bwss
  does not overwrite it: the write fails with an error to the app, and the
  next refresh shows the server's value. *(builder's call, revisable:
  Secret Service has no conflict UI, so failing is the only policy offered;
  the spec also allows a user-chosen policy.)*
- `bwss:acl` merges as the union of lines, so an "Always allow" given on
  another device survives;
- other bwss fields changed on both sides take bwss's value;
- the retry is abandoned, with an error to the app, when the fresh copy is
  trashed or deleted, no longer carries the same `bwss:id`, or now has
  notes where bwss meant to put an oversize secret. bwss never re-marks an
  item the user unmarked.

## 6. Access control

- Every read of a secret (`GetSecret(s)`), every change (`SetSecret`,
  `Label`, `Attributes`, `CreateItem` with `replace`) and every delete
  checks the caller's executable against `bwss:acl`. Anyone else gets a
  fail-closed pinentry confirmation: "Allow / Deny", then "Always allow /
  Only this time". Only an explicit OK grants anything.
- **Caller identity.** A unique bus name is pinned to the process behind
  it: pid, start time (`/proc/<pid>/stat` field 22) and identity (below).
  The pid comes from `GetConnectionCredentials`: through its `ProcessFD`
  (a pidfd, read via `/proc/self/fdinfo`, which must still name the same
  live process after the reads) when the bus provides one, otherwise from
  `ProcessID`. The pin is taken when the name appears on the bus
  (`NameOwnerChanged` with no old owner), or at its first call if that
  comes first. Every call re-reads all three; any difference (the pid was
  reused, or the process exec'd another binary) makes the caller an
  unknown application. The pin is dropped when the name leaves the bus;
  `reap_departed` sweeps any left behind. Without a pidfd, a pid reused
  between the client's connect and the daemon handling that signal is
  still taken for the new process: a window of one bus round trip.
- **Identity.** The executable (`/proc/<pid>/exe`, a ` (deleted)` suffix
  dropped), unless it is an interpreter: an executable whose basename is
  `python*`, `perl*`, `ruby*`, `node`, `nodejs`, `deno`, `bun`, `sh`,
  `bash`, `zsh`, `fish`, `dash`, `busybox`, `lua*`, `php*` or `java`.
  An interpreter running a script file is that script. The script is the
  first argument in `/proc/<pid>/cmdline` after the interpreter that is
  not an option, after `--`, or after flags that take no value in that
  interpreter only: python `-u -B -I -O -OO -q -s -S -E`; perl
  `-w -W -X -T -t`; ruby `-w`; sh, bash, zsh, dash `-e -u -x -v`; none for
  node, nodejs, fish, lua and php. A flag plain in one interpreter takes a
  value in another (`ruby -I dir`, `lua -l mod`), so the lists are per
  family. Every argument before the script must be on that list, or a
  `--` where it means "the script follows" (python, perl, ruby, the
  shells, node; not php, where `php --` reads stdin, nor fish or lua).
  Any other argument before it, any argument starting with `+` (`bash +e`,
  `+O name`), or a script name that is exactly `-` (stdin to python,
  perl, ruby and node, even after `--`), starts with `+`, or starts with
  `-` other than after `--`, means no script. `deno`, `bun`, `busybox` and
  `java` (subcommands, applets, `-jar`) never get a script identity. The
  script is resolved against `/proc/<pid>/cwd`, canonicalized, and must be
  an existing regular file. The identity, and
  ACL line, is then `<interpreter>/<script>`: both canonical absolute
  paths joined by one `/`, so the line holds the only `//` (a canonical
  path never contains one); prompts show "`<interpreter>` running
  `<script>`". A script file is treated like an application: "Always
  allow", creator lines and per-device confirmation all apply. This is a
  speed bump, like the executable: the command line is whatever the
  process says it is, so a same-user process can claim any script; and
  the environment can make a granted script run other code
  (`PYTHONPATH` or a `sitecustomize`, `PERL5OPT`, `RUBYOPT`,
  `NODE_OPTIONS`, `BASH_ENV`). A process that rewrites its title, or
  `chdir`s after starting a script given by a relative path, no longer
  resolves to a script file and falls back to the bare interpreter, asked
  every time (Allow / Deny only).
- An identity holding a control character (a newline in a path could
  plant a second `bwss:acl` line) is an unknown application.
- **Unknown applications and interpreters without a script file** (any
  other option, such as `-c`, `-m`, `-e`, `-s`, `-` for stdin, an option
  with a value, or no script argument) are asked every time with "Allow /
  Deny" only, and the prompt says why: a grant would cover every such use.
  No ACL line ever counts for these callers, they never get one when they
  create an item, and the old shared `(unknown application)` line grants
  nothing.
- **Grants are confirmed per device.** "Always allow" appends to
  `bwss:acl` in the item, so it syncs, and a creating app gets the first
  line. But a line counts on a device only once that device confirmed it.
  The set of confirmed lines is device state
  (`$XDG_STATE_HOME/dybw/tools/bwss/acl-confirmed`, mode 0600, never
  synced): tags `HMAC(K, bwss:id ‖ 0x00 ‖ exe)` with
  `K = user_key.derive("acl-confirm")` (MAC half), sealed as a whole under
  `K` as `{ "format": 2, "set": "<EncString>" }`, like the write queue.
  - A grant made on this device (an "Always allow", or the creator's line)
    is recorded when it is made.
  - A line found in the item but not in the set triggers a one-time
    "Allow `<exe>`, granted on another device?" (Allow / Deny). Allow
    records it; Deny records a denial, so that caller is refused on this
    device without asking until the line changes. Only the user's own
    answer is recorded: a prompt that fails or times out denies that one
    request and records nothing.
  - When a line is gone from the item, so is whatever was recorded about
    it: every keyring rebuild (unlock, a refresh that brings changes)
    keeps only the tags of the (`bwss:id`, line) pairs the items hold, and
    a call by a caller whose line is absent drops its tag too. A line
    revoked elsewhere and added back later is asked about again.
  - A file that is not `format: 2` is set aside. One that cannot be read
    or opened with `K` (another account, damage) reads as empty and is
    never overwritten; decisions then stay in memory until the daemon
    exits, with a warning in the log.
  - The memory backend's items never leave the daemon, so its lines count
    without confirmation.
- `bwss acl off` disables checks on this device (gnome-keyring
  behaviour); it is device state, never a config key (§10). The `session`
  collection is exempt.
- Labels and attributes of marked items are readable by any process on the
  bus while unlocked; that is how the Secret Service API works. This is why
  marking is opt-in: the user decides which items' metadata apps may see.
- Limits: this is a speed bump, not a sandbox. Same-user processes can
  ptrace each other (§10, §11). Pinning stops pid reuse and an exec after
  the first call, but not a process that connects, forks, and execs an
  allowed binary in the parent before its child's first call: the bus
  still reports the parent, which now runs that binary. A check based on
  the process cannot close this.

## 7. Unlocking, locking and the locked index

Unchanged from `legacy`:

- One Bitwarden master password unlocks everything, through pinentry (3
  attempts) on the first request or `bwss unlock`. Failed CLI unlocks (a
  wrong `--password-stdin`, or a `bwss unlock` prompt that ends locked) are
  delayed 2 s: attempts take turns and the delay never holds the interactive
  unlock. This is a speed bump against other processes of the
  same user, not a defence against one that can also read the bus.
- Per bus client: at most 64 sessions (its oldest is closed first; 4096 in
  all) and 16 outstanding prompts (its oldest
  unstarted one is dismissed). Only the bus name that opened a session may
  close it. When a client leaves the bus its sessions and prompts are freed; at
  the global limit, departed clients are reaped first, then the oldest session
  of the client holding the most is closed.
- Lock on request, after `lock_timeout_minutes` (default 60), and on SIGTERM: keys and
  decrypted items are zeroized, the API session is dropped.
- The locked index (`~/.cache/bwss/locked-index.json`) keeps, per marked
  item, its id, its collection and SHA-256(salt ‖ name ‖ 0 ‖ value) of each
  attribute (derived ones included), with a random per-install salt, so
  libsecret can find and unlock a locked item after a restart. It covers
  marked items only.

## 8. Data model and sync

### 8.1 Data model

Three layers, from the server inward:

```mermaid
flowchart LR
  S[(Bitwarden server<br/>ciphers, folders, profile)]
  C[Vault cache<br/>sync.json: ciphertext]
  M[Marked set<br/>decrypted marked items]
  K[Keyring<br/>D-Bus objects]
  Q[Write queue<br/>queue.json: patches]
  S -- /sync --> C
  C -- scan --> M
  M --> K
  K -- app writes --> P{{Patch}}
  P -- online --> S
  P -- offline --> Q
  Q -- flush --> S
  P -- applied locally --> C
```

**Vault cache** (`~/.cache/bwss/sync.json`, mode 0600). The last `/sync`
response as the server sent it, so everything in it is still ciphertext,
plus the KDF parameters and the account revision date. Every successful
write replaces the cipher it touched with the server's answer. It is the
only copy of the vault on disk and the source for offline unlock.

**Marked set** (memory only, while unlocked). Built by scanning the cache:

```
MarkedItem {
  cipher_id, revision_date        // which server object, which version
  id                              // value of bwss:id
  collection, label, attributes   // explicit bwss:attr:* + derived
  secret: Zeroizing<Vec<u8>>, content_type
  secret_source: Field | BwssNotes | NoteBody | LoginPassword
  secret_mark                     // keyed fingerprint of the decrypted value
  acl: Vec<String>, created, modified
}
duplicates: Vec<(id, cipher_ids)>
registry: BTreeMap<collection id, { label, created, deleted }>
```

`secret_source` records the value source (§3.2), so a write knows which
part it may replace. `secret_mark` is HMAC-SHA256 of
`bwss:id ‖ 0x00 ‖ text` under a key derived from the user key (HKDF,
purpose `value-mark`), where `text` is the value source's **decrypted**
text before any base64 decoding; the Obsidian plugin computes its mark the
same way. A retry can then tell whether the value source changed on the
server (§5.6) without keeping a second copy of the value (spec §10).
The mark is never taken over ciphertext: official clients re-encrypt every
value with a fresh IV on any save, so an unchanged value would look
changed. The id keeps two items holding the same secret from sharing a
mark. A per-cipher scan cache keyed by
`(cipher_id, revision_date)` remembers "unmarked" for ciphers that have not
changed, so a refresh only decrypts field names of changed ciphers.

**Keyring** (memory only). The Secret Service view: collections and items
keyed by `id`, the escaped object paths, and the locked index. It knows
nothing about Bitwarden.

**Patch**: every write, online or queued, is expressed as a change to
bwss's own parts of one item, never as a whole item body:

```
Op =
  | Create  { id, collection, body }            // the full new secure note
  | Patch   { id, base_revision, cipher_id?,
              set: [(field, value, hidden)],    // bwss fields to write
              remove: [field],                  // bwss fields to drop
              acl_add: [line],                  // merged as a union
              value: Keep                       // or write the value source:
                   | Set { source, value, base_mark, owned } }
                                                // §5.2; base_mark detects a
                                                // changed source; owned: an
                                                // earlier binary write made
                                                // bwss:password the source
  | Delete  { id, base_revision, cipher_id? }   // §5.4, decided on replay
  | Registry{ collection, entry }               // merged, §4
```

An op names its item by `id`, not by cipher id, because a queued create
has no cipher id yet. The cipher id is looked up when the op runs. The
optional `cipher_id` on `Patch` and `Delete` records the cipher the op was
read from, as a hint only: when the item cannot be found by `id`, the op
waits only while *that* cipher is still there but cannot be read right now,
and is dropped as gone otherwise. One unreadable item elsewhere in the
vault can therefore never hold up the queue. Ops written without it keep
the older behaviour.

**Write queue** (`~/.local/state/bwss/queue.json`, mode 0600). The ordered
list of ops not yet accepted by the server, sealed as a whole: the file is
`{ "format": 2, "ops": "<EncString>" }`, one EncString under the user key
holding every op with its ids, fields, values, marks, cipher ids and
revision dates. Only `format` is plain. The queue, the cache and the locked
index are device state (spec §10): they are never synced or copied to
another device. A queued op is applied to the cache right away, so reads on
this device see it before the server does.

**Locked index** (`~/.cache/bwss/locked-index.json`), as in §7.

### 8.2 Unlocking

1. Online: prelogin (KDF parameters), API-key login, `GET /sync`, decrypt
   the user key with the master key. Save the response as the cache.
2. Offline, when step 1 fails transiently (connection errors, 429, 5xx):
   load the cache instead. The password check is identical (the MAC of the
   protected user key).
3. Re-apply every queued op to the loaded cache, so pending writes stay
   visible.
4. Scan: for every personal login or secure note not in the trash, decrypt
   the item key and the field names; for marked ones, decrypt the rest and
   build a `MarkedItem`. Resolve duplicate ids (§3.3). Read the registry.
5. Build the keyring and the locked index, and flush the queue in the
   background.

### 8.3 Writing

```mermaid
sequenceDiagram
  participant A as App
  participant D as bwss
  participant S as Server
  A->>D: SetSecret / Label / Attributes / Delete / CreateItem
  D->>D: authorize (§6), build op
  D->>S: PUT/POST with lastKnownRevisionDate
  alt accepted
    S-->>D: new cipher
    D->>D: replace cipher in cache, rescan it, emit signal
  else out of date
    D->>S: GET /ciphers/{id}
    D->>D: abort checks (§5.6), re-apply op to fresh copy
    D->>S: PUT again (at most 3 attempts)
  else transient failure
    D->>D: append op to queue, apply to cache, emit signal
  end
  D-->>A: result
```

- Applying an op always means: take the current copy of the cipher (the
  server's on retry or flush, the cache's when queuing), run the abort
  checks (including the `base_mark` check on the value source), apply the
  op's field changes and merges (`bwss:acl` union, registry union), write
  the value source with password history when it is the login password,
  and send the result.
- Once an op is queued, later ops for any item queue behind it, so order
  is kept across items. *(builder's call, revisable: ordering per item
  would let unrelated writes through sooner.)*
- A `Delete` saves the stripped item first and trashes it only if the
  server's answer holds no foreign content (§5.4).
- A permanent error (4xx other than out-of-date and 429) drops the op,
  logs it and rescans the item from the server, so the local view returns
  to the truth.

### 8.4 Refreshing

Every `sync_interval_seconds` (default 300), on `bwss sync`, and right after
an unlock:

1. Flush the queue in order. A transient failure stops the flush; the rest
   stays queued.
2. `GET /accounts/revision-date`. If it equals the cached one, stop here.
   *(builder's call, revisable: this saves a full `/sync` on most ticks.)*
3. `GET /sync`, replace the cache, re-apply ops still queued.
4. Rescan, only changed ciphers (§8.1), and diff the marked set by `id`:
   - new id: `ItemCreated` (this includes an item the user just marked);
   - id gone: `ItemDeleted` (unmarked, trashed or deleted elsewhere), but
     not for an item that became uninspectable (§3.4);
   - same id, new revision: `ItemChanged`;
   - collections appearing or disappearing: `CollectionCreated` /
     `CollectionDeleted`.
5. Rewrite the locked index.

No sync happens while locked: the user key and the API token are gone.

### 8.5 Across devices

- Everything apps can see lives in the item: id, label, attributes,
  collection, content type, ACL, and the secret. Two devices that have
  both synced therefore show the same keyring.
- Until the next refresh, a device does not see another device's changes
  (up to `sync_interval_seconds`).
- Two devices creating the same item while apart produce two items with
  different ids, and apps searching by attributes see two matches. bwss
  does not merge them; `bwss status` lists items with identical collection
  and `bwss:attr:*` sets.
- Concurrent edits of the same item merge field by field (§5.6); the
  registry and `bwss:acl` merge as unions; a value source changed on both
  sides fails the app's write rather than overwriting.
- The mass-clear guard of spec §10 applies to tools that keep local
  copies of values. bwss keeps none (it reads values from the encrypted
  vault cache), so per the spec it has nothing to clear and nothing to
  guard: an item leaving the keyring is still in Bitwarden.

## 9. Sessions, prompts and the bus

Unchanged from `legacy`: `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7`
sessions owned by the opening bus name (at most 4,096); pinentry over
Assuan with 120 s timeouts; `Prompt.Completed` carries a result of the
success type even when dismissed; the control interface
`io.github.dynamotn.bwss.Control1`.

Bus names. The daemon must be the primary owner of both
`io.github.dynamotn.bwss` and `org.freedesktop.secrets`, or it exits with an
error naming the current owner's executable and pid, after releasing a name
it already took. Both are requested with `DO_NOT_QUEUE` and without
`ALLOW_REPLACEMENT`, so no other client can take them over with
`REPLACE_EXISTING`. `--replace` adds `REPLACE_EXISTING` for
`org.freedesktop.secrets` only, to take over from another provider that
allows it; the control name is claimed first and never replaced, since
whoever holds it would receive `bwss unlock --password-stdin`.

Control methods: `UnlockInteractive() -> b` (the daemon prompts through its
own pinentry, so no password crosses the bus; throttled like a failed
password), `UnlockWithPassword(s)`, `Lock()`, `Sync()` and
`Status() -> (b, u, s)`.

`UnlockWithPassword` is refused, before the password is tried, unless the
caller (identified as in §6) runs the daemon's own executable
(`current_exe()`, canonical paths, ` (deleted)` ignored): it exists for
`bwss unlock --password-stdin` only. This is a speed bump with the
same-user limits of §10: a process of the user can exec the bwss binary or
ptrace it.

## 10. Configuration and CLI

bwss reads the file every dybw tool shares, `$XDG_CONFIG_HOME/dybw/config.toml`
(dybw ADR 0008, profiles §1). It has no file of its own.

```toml
default = "personal"

lock_timeout_minutes = 60        # shared by every profile
sync_interval_seconds = 300
pinentry = "pinentry-gnome3"

[profiles.personal]
server_url = "https://vault.bitwarden.com"
email = "you@example.com"

[bwss]
profile = "personal"             # default: `default`
folder = "secret-service"        # where new items are created
backend = "bitwarden"            # or "memory" (with memory_password) for tests and demos
```

- **One profile.** bwss serves `[bwss] profile`, or the file's `default`.
  The account (`server_url`, `email`) comes from that profile.
  `lock_timeout_minutes`, `sync_interval_seconds` and `pinentry` resolve
  from the profile, then the top level, then the built-in default (60,
  300, `pinentry`). `auth` must resolve to `"api-key"`, the only login bwss
  has. The memory backend needs no profile.
- **Validation.** bwss checks the top level and the profile it serves
  against the key registry of profiles §1, and `[bwss]` against its four
  keys (`profile`, `folder`, `backend`, `memory_password`). An unknown key
  there is an error, and so is a shared key (`default`,
  `clipboard_clear_seconds`) inside a profile. Every other table
  (`[ssh_agent]`, `[obsidian]`, other profiles, a newer tool's section) is
  ignored. The registry is a test fixture
  (`tests/fixtures/config-registry.toml`) that mirrors the table in dybw.
- **Nothing in the file weakens a check**, because it may be synced:
  - an `acl` key anywhere is an error. Turning the ACL off is device
    state: `bwss acl off` (asked on the terminal, refused when stdin is not
    one) creates `$XDG_STATE_HOME/dybw/tools/bwss/acl-off`, and `bwss acl
    on` removes it. The daemon reads it at start.
  - `pinentry` is resolved to an absolute path (a bare name through
    `PATH`). The daemon refuses to start unless that path is in `/usr/bin`,
    `/usr/local/bin`, `/opt/homebrew/bin` or `/run/current-system/sw/bin`,
    and neither the program (after links) nor that directory is writable by
    the user: owned by them, writable by a group they are in or by anyone,
    or the user is root.
- **The API key** lives in `$XDG_STATE_HOME/dybw/profiles/<profile>/credentials`
  (TOML: `identity_origin`, `client_id`, `client_secret`), mode 0600,
  shared with the dybw CLI. It must be a regular file owned by the user,
  not a link. `identity_origin` is the `scheme://host[:port]` of the
  identity URL it was entered for. When the profile's server resolves to
  another origin, the daemon refuses to start and asks for `bwss login`;
  the stored key is kept, not cleared. `Api::login` checks the same binding
  before every token request.
- **Device id:** `$XDG_STATE_HOME/dybw/profiles/<profile>/devices/bwss`.
  The cache (`$XDG_CACHE_HOME/bwss`), the queue (`$XDG_STATE_HOME/bwss`) and
  the locked index keep their paths. The daemon creates these directories,
  or tightens them, to 0700.
- **Migration.** When `~/.config/bwss/config.toml` exists and the dybw file
  has no `[bwss]`, every command that reads the config stops and names
  `bwss config migrate`. That command reuses a profile with the same server
  and email or adds `[profiles.bwss]`; moves `folder` and `backend` (and
  `memory_password` for the memory backend) into `[bwss]`; turns a non-zero
  `idle_lock_minutes` into a `lock_timeout_minutes` override and a
  `prompter` into a `pinentry` override, after checking it as above;
  makes `acl = "off"` device state only if the user confirms it on the
  terminal; moves the API key (bound to the profile's origin) and the
  device id. It edits the dybw file as text, so comments survive, and
  writes nothing unless the result passes validation. Old files are renamed
  `*.migrated`, never deleted.

```
bwss daemon [--replace]
bwss unlock [--password-stdin]
bwss lock | sync | status
bwss login --client-id ID [--client-secret-stdin]
bwss acl off | on
bwss config migrate
```

`bwss unlock` calls `UnlockInteractive`: the daemon shows the pinentry and
no password crosses the bus. This is the safe way to unlock.

`--password-stdin` is for login hooks that accept the risk below. Before
sending the password it resolves the owner of `io.github.dynamotn.bwss`
(`GetNameOwner`, `GetConnectionUnixProcessID`, `/proc/<pid>/exe`) and
refuses, naming that executable, unless it is the CLI's own `current_exe()`
(canonical paths; a ` (deleted)` suffix from an upgrade is ignored) and
`/proc/<pid>/cmdline` is `<bwss> daemon [--replace]`. The call then goes to
that unique name, so the owner cannot change in between. The command line
matters because the bus reports the pid of whoever opened the connection: a
squatter can fork, keep the connection in the child and exec a blocking
`bwss unlock` in the parent. Without `/proc` (non-Linux), `--password-stdin`
is refused. The CLI and the daemon must be the same installed file.

What the owner check stops: a squatter that is not running bwss, and the
fork form that execs `bwss unlock`. What it cannot stop: a process of the
same user that forks, keeps the name in the child and execs a real
`bwss daemon` in the parent (pointed at another bus, hung before it claims
its names, or stopped with SIGSTOP), so that the exe and the command line
both pass; or one that can ptrace the daemon or the CLI. A check based on
the pid cannot close this. Processes of the same user are not a security
boundary for `--password-stdin`.

`bwss status` additionally reports duplicate ids and likely duplicate items
(§3.3, §8), by id and label only, never secrets.

## 11. Security model

| Asset | Protection |
|---|---|
| Unmarked items | Only field names are decrypted; nothing reaches the bus, the index or logs |
| Marked items' metadata | On the bus while unlocked, by the user's choice (marking) |
| Secrets | ACL plus fail-closed confirmation; DH-AES sessions on the bus |
| User data in marked items | Writes touch bwss fields and the value source only; a new secret never goes into the user's password or notes; trash only when no foreign content (other tools' fields included) is left |
| Master password, user key | Local only, zeroized, dropped on lock |
| API key | 0600 regular file owned by the user, bound to its identity origin and never sent to another; https only except loopback, redirects disabled |
| Settings that weaken a check | Never read from the synced config file: ACL off is device state, `pinentry` must be a system program the user cannot replace (§10) |
| Disk | Bitwarden ciphertext only (cache, queue, ACL confirmations); hashed locked index |
| Server input | KDF bounds, MAC checked before decrypt, error text clipped |

Notes:

- The marker is ciphertext under the user key, so the server can not mark
  a personal item on its own. (For organization items it could, through
  any member with write access; see §12.)
- bwss holds the security invariants of spec §11 as written there.
- The bus names are never replaceable. Plain `bwss unlock` keeps the
  password inside the daemon and is the safe path. `bwss unlock
  --password-stdin` sends it only to a `bwss daemon` process running the
  CLI's own file (§10). That stops look-alike services that are not bwss,
  but not a process of the same user that forks and execs a real
  `bwss daemon`, nor one that can ptrace. Same-user processes are not a
  security boundary for `--password-stdin`.
- `bwss:acl` comes from the item, and anyone who can edit the item in
  Bitwarden can add a line. A line counts on a device only after that
  device granted or confirmed it (§6), so a line slipped in elsewhere
  asks first.

## 12. Later: organization items

Left out of the first version. When they arrive, bwss adopts spec §9 as
written; in bwss's terms:

- Organization keys are RSA-OAEP encrypted to the user's public key; the
  private key is in `profile.privateKey`, encrypted with the user key. Use
  an RSA implementation without RUSTSEC-2023-0071 (for example
  `aws-lc-rs`), not the `rsa` crate.
- Opt-in in the config, per organization later.
- A personal item always wins over an organization item with the same id
  (§3.3).
- **Claims**: an organization item claiming a `bwss:id` the device already
  knows (a base entry or a keyring item with that id, even with the same
  value) is shown to apps only after the user confirms it through
  pinentry. Only an id new to the device is taken without asking. This
  needs a device-local base (cipher id, revision, value mark per id),
  never synced.
- bwss never writes an app's value into an organization item unless the
  base already binds the id to that cipher. Declining a claim keeps the
  local value as a new personal item (§5.1), which then wins.
- Items with `edit: false` are read-only to apps; items with
  `viewPassword: false` are skipped.
- `bwss:acl` on an organization item grants nothing without a local
  confirmation.

## 13. Architecture

The module split of `legacy` is kept. The builder may port code from `legacy`
(crypto, API client, sessions, pinentry, ACL identity, D-Bus objects,
config, fsutil), since none of those change in substance.

| Module | Change from `legacy` |
|---|---|
| `bw/crypto.rs` | Adds the `value-mark` key derivation |
| `bw/api.rs` | Adds `GET /ciphers/{id}` and `GET /accounts/revision-date`; folder writes are only needed for the keyring folder |
| `bw/items.rs` | Rewritten: marker scan (field names only), the read and write rules of §3 and §5, foreign-content check, field-level re-apply on conflict |
| `backend/bitwarden.rs` | Snapshot built from marked items and the collection registry; no sub-folders, no `whole_vault`, no `vault-acl` |
| `model.rs` | No `read_only`; reversible path escape |
| `daemon.rs`, `dbus.rs` | No `vault` collection or read-only checks; delete calls the §5.4 rule |
| `acl.rs`, `acl_confirm.rs` | Caller identity pinned per bus name; interpreter detection; the device-local confirmation set (§6) |
| `config.rs`, `migrate.rs` | The shared dybw file (§10): registry validation, profile resolution, the `pinentry` rule, origin-bound credentials, `bwss config migrate` |
| `keyring.rs`, `session.rs`, `prompter.rs`, `fsutil.rs`, `main.rs` | Unchanged apart from removing `whole_vault`; `main.rs` adds `bwss acl` and `bwss config migrate` |

## 14. Compatibility with `legacy`

None, by decision. There is no migration and no special case for items or
files that the folder-based bwss (branch `legacy`) wrote:

- Items `legacy` created carry `bwss:id`, so they are simply marked items
  under the rules above. Their secret is read from `login.password` or the
  notes, and an app's next write goes back there (with password history
  for a login). Their password or notes count as foreign content, so a
  delete strips the bwss fields and keeps the item. Users who want a clean
  start delete those items, or their bwss fields, by hand.
- Collections `legacy` built from sub-folders are not recognised; their
  items show up in `login` until they get `bwss:collection`.
- `whole_vault` is an unknown key of the old `~/.config/bwss/config.toml`,
  so `bwss config migrate` refuses that file until the key is removed.
- The cache, queue and locked index keep their paths but carry
  `"format": 2`. A file without it (left by `legacy`) is not read: the
  cache and the index are rebuilt, and a queue is renamed
  `queue.json.legacy` with a warning, never replayed. `vault-acl` is not
  read.

## 15. Verification

- **Unit tests** for each rule here, in particular:
  - reading precedence (label, secret), including a present but empty
    `bwss:password` and a duplicated field (the first counts), derived
    attributes;
  - unmarked items: only field names decrypted (assert that decrypting the
    name, notes or login of an unmarked cipher never happens, for example
    with a counting key in tests);
  - path escape is reversible and collision-free;
  - duplicate ids resolved the same way regardless of order;
  - write-back to each value source: `bwss:password`, bwss's notes, a
    note's text, the login password with history (at most 5) and
    `passwordRevisionDate`; everything else, `obsidian:*` and `dybw:*`
    fields included, untouched; a new item never uses the notes; size
    fallback to notes and its refusal when the notes hold user text;
  - binary values (ADR 0005): a binary write to a hand-marked login
    creates a hidden `bwss:password` with `bwss:encoding=base64` and
    leaves `login.password` and its history unchanged; the same on a
    hand-marked note leaves its text unchanged; a later text write goes to
    that field and removes `bwss:encoding`; an item whose source is the
    login password (or a note's text) and that carries
    `bwss:encoding=base64` is skipped and reported, never decoded;
  - delete: trash versus strip, for each kind of foreign content,
    including another namespace's marker;
  - conflict re-apply keeps a concurrent foreign edit, and fails when the
    value source changed;
  - an uninspectable item is not reported deleted;
  - the collection registry round trip.
- **End-to-end** (pytest under `dbus-run-session`, against Vaultwarden,
  checked by the independent Python client in `tests/e2e/bwclient.py`):
  - an item marked by the other client appears after `bwss sync`, findable
    by `bwss:name`; an app write on that login updates its password, with
    the old one in the history, and the other client sees it;
  - a login with a `bwss:password` field: the app write lands in the
    field and the login password stays;
  - a binary secret stored on a hand-marked login lands in a new
    `bwss:password`, and the other client still sees the old login
    password with an unchanged history;
  - an item carrying both `bwss:id` and `obsidian:id` is not trashed by a
    delete;
  - deleting a hand-marked login strips bwss fields and keeps the item;
    deleting an item bwss created trashes it;
  - unmarking in the other client removes it from the keyring;
  - a cloned item does not change which item apps see;
  - all existing scenarios from `legacy` (unlock, ACL, offline queue,
    locked index, collections, sessions).
- `cargo fmt --check`, `cargo clippy --locked --all-targets`,
  `cargo test --locked`, the ignored perf test, and `cargo audit`.

## 16. Left to the builder

- Internal structure inside each module, error types, log wording.
- Exact layout of `bwss status` output.
- Whether to port code from `legacy` or rewrite it, module by module.
