//! What each PAM hook does, in safe code (the ADR 0006 table).

use std::ffi::CStr;

use crate::contract::{LOCK, LOGIN, lock_payload, nonempty, password_entries};
use crate::ffi::{PAM_AUTHTOK, PAM_OLDAUTHTOK, PAM_USER, Pam, user, write_as};

/// `auth`: keep a copy of the password the stack already read; never prompt.
pub fn authenticate(pam: &Pam) {
    if let Some(token) = nonempty(pam.item(PAM_AUTHTOK)) {
        pam.keep(token);
    }
}

/// `session` open: hand the kept copy to the user's keyring, then wipe it.
pub fn open_session(pam: &Pam) {
    if let Some(token) = pam.take() {
        put(pam, &[(LOGIN, &token)]);
    }
}

/// `session` close: ask the consumer to lock; the request carries no secret.
pub fn close_session(pam: &Pam) {
    let session = pam.env(c"XDG_SESSION_ID");
    put(pam, &[(LOCK, lock_payload(&session))]);
}

/// `password`: the old and the new token, in the update phase only.
pub fn chauthtok(pam: &Pam, flags: i32) {
    let (old, new) = (pam.item(PAM_OLDAUTHTOK), pam.item(PAM_AUTHTOK));
    put(pam, &password_entries(flags, &old, &new));
}

/// Writes `entries` into the keyring of the user being logged in, as them.
fn put(pam: &Pam, entries: &[(&CStr, &[u8])]) {
    if entries.is_empty() {
        return;
    }
    if let Some((uid, gid)) = user(&pam.item(PAM_USER)) {
        write_as(uid, gid, entries);
    }
}
