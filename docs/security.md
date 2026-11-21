# bwss security model

What bwss protects, how, and where it stops. The full model is in
[design.md](design.md) §11.

## Crypto and keys

- bwss runs on dybw-core, which implements Bitwarden's client-side crypto
  (PBKDF2 or Argon2id, HKDF, AES-256-CBC with HMAC, and the newer COSE keys
  and blob items). Only ciphertext crosses the network.
- The master password is used only locally, to derive keys, and never
  leaves the machine. The API key only *authenticates*; decrypting still
  needs the master password.
- Key material is zeroized when the keyring locks.
- On Linux the daemon disables core dumps and ptrace-style attach. It does
  not `mlock` memory.

## Locking

The keyring locks on `bwss lock`, after `lock_timeout_minutes` without use,
when the machine goes to sleep, and when the session locks (systemd-logind
on the system bus; without it bwss logs a warning and carries on).

Run from a login session, bwss follows that session's lock. Run as a
systemd user unit, which belongs to no session, it follows the screen lock
of any session of your own user, and no other user's. Lock signals are
accepted only from logind itself.

## Unlocking

- `bwss unlock` is the safe way: the daemon asks through its own pinentry,
  so no password crosses the bus.
- `bwss unlock --password-stdin` sends the password over the session bus to
  the process that owns bwss's control name, but only after checking that it
  is a `bwss daemon` of your user running the same installed file as the
  CLI, by its command line and start time. Because the daemon is not
  dumpable, its `/proc/<pid>/exe` cannot be read, so this check is best
  effort: it stops a look-alike service, not another process of yours that
  starts a real `bwss daemon` to pass it. Use it only if you accept that.
- Only the `bwss` CLI itself may send the master password to the daemon
  (`io.github.dynamotn.bwss.Control1.UnlockWithPassword`); any other
  executable is refused.

## Per-app access control

- Every read, change and delete of a secret checks the caller against the
  item's `bwss:acl`. The check fails closed: only an explicit *Allow*
  grants access.
- Apps are identified by executable path (`/proc/<pid>/exe`), pinned to the
  process behind each bus connection. A script run from a file
  (`python3 ~/bin/backup.py`) is an app of its own, identified by
  interpreter and script path.
- Interpreters running code from `-c`, `-m` or stdin, and apps bwss cannot
  identify, are asked every time and never offered *Always allow*. Programs
  that are themselves not dumpable (gpg-agent, sandboxed browsers) cannot
  be identified, so they are asked every time too.
- Grants (`bwss:acl`) sync with the item, but a device honours one only
  after it granted or confirmed it there. Those decisions live in
  `~/.local/state/dybw/tools/bwss/acl-confirmed`, sealed with your vault
  key and never synced; deleting the file makes bwss ask again.
- Labels and attributes of marked items are readable by any process on the
  bus while unlocked; that is how the Secret Service API works, and why
  marking is opt-in.

## On disk

- On disk there is only Bitwarden ciphertext, plus the locked index.
  Offline writes are sealed under a key of their own, derived from your
  vault key.
- The locked index (`~/.cache/bwss/locked-index.json`) holds salted
  SHA-256 hashes of the attributes apps set, never secrets: the same
  trade-off gnome-keyring makes. The salt is in the same file, so anyone who
  can read it can test guesses of those values offline. bwss accepts this
  because apps must find locked items before the first unlock.
- Item names, usernames and URIs stay out of the index, and off the bus,
  unless you run `bwss derive on` on that device.

## On the network

- HTTPS is required (plain http only for `localhost`), and redirects are
  not followed, so the API key cannot be bounced to another host. The API
  key is bound to the identity server it was entered for and is never sent
  to another one.
- Only authenticated encryption is accepted (EncString type 2, and type 7
  on COSE accounts), and server-supplied KDF parameters are range-checked
  to stop downgrades and resource exhaustion. Server answers are capped at
  256 MiB.
- A server cannot quietly weaken this device: a weaker KDF than the one
  pinned here, an older account security state, or an item older than the
  copy on this device stops the unlock or is held back until you accept it
  (`bwss kdf accept`, `bwss security accept`, `bwss sync --accept-rollback`).
  Items that need a newer bwss are left alone, never treated as deleted.

## The bus and what you see

- bwss will not start unless it owns both of its bus names
  (`org.freedesktop.secrets` and `io.github.dynamotn.bwss`), and no other
  process can take them over afterwards.
- Secrets cross D-Bus encrypted whenever the client asks for it
  (`dh-ietf1024-sha256-aes128-cbc-pkcs7`, the libsecret default).
- A prompt belongs to the client that created it; nobody else can start or
  dismiss it, and a client that leaves takes its pending action with it.
- Text bwss shows you, such as an app's path or an item's label in a
  pinentry prompt and server error messages, is put on one line with
  control characters, ANSI escapes and invisible bidi characters removed, so
  it cannot add or reorder text.

## A synced config cannot weaken anything

- The config file may travel with your dotfiles, so nothing in it switches
  a protection off. Access control and derived attributes are device state,
  set with `bwss acl` and `bwss derive` and confirmed on the terminal.
- The pinentry must be a program you cannot write to, nor any directory
  above it. A Homebrew-installed bwss also accepts a pinentry from the same
  Homebrew prefix, but never one under your home directory. Otherwise the
  daemon refuses to start.
- bwss never runs as root.

## What bwss is not: a sandbox

Access control identifies apps by executable path and scripts by the script
path in their command line. Any process running as your user can still
inspect other processes, rewrite its own command line, slip code into an
allowed script through the environment (`PYTHONPATH`, `PERL5OPT`,
`RUBYOPT`, `NODE_OPTIONS`, `BASH_ENV`), or fork and exec an allowed binary
to pose as it. bwss stops quiet cross-app reads, not a determined local
attacker.
