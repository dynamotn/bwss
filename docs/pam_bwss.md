# pam_bwss

`pam_bwss.so` is a small PAM module (dybw ADR 0006) that hands your Linux
login password to the process that unlocks your vault with it, through your
kernel keyring. The [README](../README.md#unlock-at-login-with-pam_bwss)
has the install steps; this page has the details.

> **The consumer is not released yet.** The `login` protector of the dybw
> agent, which reads these entries and unlocks with them, is still to come.
> Until then the entries simply expire, and you unlock with `bwss unlock`
> or on first use.

## What it does

It reads the password the stack already collected and never prompts. It
talks to no bus, socket or network, runs no KDF, logs nothing and writes no
file. Every hook returns `PAM_IGNORE`, so it never changes the outcome of a
login. A login without a password (fingerprint, SSH key, automatic login,
smartcard) leaves nothing.

| When | It adds to your user keyring (`@u`) |
|---|---|
| session open, after a password login | `dybw:login`: the password |
| a screen locker's unlock (`pam_setcred` with `PAM_REFRESH_CRED` or `PAM_REINITIALIZE_CRED`) | `dybw:login`: the password |
| session close | `dybw:lock`: a lock request (the session id, no secret) |
| password change | `dybw:login-old`, then `dybw:login`: the old and the new password |

- The password goes only to the user it was typed for: a stack that changes
  the user after authentication (`sudo -u`, `doas`) hands nothing over.
- Each entry is a `user` key that only you can view, read and search, and
  the kernel drops it after 60 seconds.
- Password logins over SSH do not reach the session hook (OpenSSH runs PAM
  authentication in a separate process).
- With a `password required pam_unix.so` stack the module also runs after a
  change that `pam_unix` then fails to write, so `dybw:login-old` and
  `dybw:login` may describe a change that did not happen. The consumer keeps
  its old wrap until a later login verifies the new password.
- Any process of your own user can write `dybw:login` or `dybw:lock` into
  your keyring. That can delete the `login` protector or lock your
  profiles, but never unlock or reveal anything; this denial of service is
  accepted by design (ADR 0006).

## Build and install

Build it with a glibc toolchain (the static musl release cannot build a
shared library), then install it as root into your distribution's module
directory:

```sh
cargo build --locked --release -p pam_bwss
sudo install -o root -g root -m 644 target/release/libpam_bwss.so <moduledir>/pam_bwss.so
```

| Distribution | `<moduledir>` |
|---|---|
| Debian, Ubuntu | `/usr/lib/x86_64-linux-gnu/security` (`/usr/lib/aarch64-linux-gnu/security` on arm64) |
| Arch | `/usr/lib/security` |
| Fedora | `/usr/lib64/security` |

## Add it to the PAM stack

bwss never edits `/etc/pam.d`; add the lines yourself. Each is `optional`
and goes **after** `pam_unix`, never between a `[success=N]` line and the
module it jumps to. Keep a root shell open while you try a new PAM stack.

**Debian, Ubuntu.** Save this as `/usr/share/pam-configs/bwss`, then run
`sudo pam-auth-update` and tick it:

```
Name: Hand the login password to the dybw agent (pam_bwss)
Default: no
Priority: 0
Auth-Type: Additional
Auth:
	optional	pam_bwss.so
Session-Interactive-Only: yes
Session-Type: Additional
Session:
	optional	pam_bwss.so
Password-Type: Additional
Password:
	optional	pam_bwss.so
```

`Session-Interactive-Only: yes` puts the session line in
`common-session` only, not in `common-session-noninteractive`, so cron jobs
and other non-interactive sessions never run it.

**Arch, Fedora and others.** Add these at the end of the matching section of
`/etc/pam.d/login` and of your display manager's file (`gdm-password`,
`sddm`, `lightdm`), and the `password` line to `/etc/pam.d/passwd`:

```
auth      optional  pam_bwss.so
session   optional  pam_bwss.so
password  optional  pam_bwss.so
```

Add the `auth` line to your screen locker's file too, so an unlock hands the
password over again.

## Testing

`pam_bwss` has its own suite under `tests/pam`, run with `pamtester` as root
inside a container; see [development.md](development.md#pam_bwss).
