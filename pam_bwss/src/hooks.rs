//! What each PAM hook does, in safe code (the ADR 0006 table).

use std::ffi::CStr;

use crate::contract::{Kept, LOCK, LOGIN, lock_payload, nonempty, password_entries, setcred_hands_over};
use crate::ffi::{PAM_AUTHTOK, PAM_OLDAUTHTOK, PAM_USER, Pam, user, write_as};

/// `auth`: keep a copy of the password the stack already read, bound to the
/// user it was given for; never prompt.
pub fn authenticate(pam: &Pam) {
    if let Some(token) = nonempty(pam.item(PAM_AUTHTOK)) {
        pam.keep(Kept::new(pam.item(PAM_USER), token));
    }
}

/// `auth` setcred: a screen locker's refresh hands the copy over as session
/// open does; a login's `PAM_ESTABLISH_CRED` leaves it to session open.
pub fn setcred(pam: &Pam, flags: i32) {
    if setcred_hands_over(flags) {
        hand_over(pam);
    }
}

/// `session` open: hand the kept copy to the user's keyring.
pub fn open_session(pam: &Pam) {
    hand_over(pam);
}

/// `session` close: ask the consumer to lock; the request carries no secret.
pub fn close_session(pam: &Pam) {
    let session = pam.env(c"XDG_SESSION_ID");
    put(pam, &[(LOCK, lock_payload(&session))]);
}

/// `password`: the old and the new token, in the update phase only. They are
/// this call's own items, which the password stack read for `PAM_USER`.
pub fn chauthtok(pam: &Pam, flags: i32) {
    let (old, new) = (pam.item(PAM_OLDAUTHTOK), pam.item(PAM_AUTHTOK));
    put(pam, &password_entries(flags, &old, &new));
}

/// Takes (and wipes) the kept copy, and writes it as `dybw:login` only when
/// `PAM_USER` is still the user it was given for.
fn hand_over(pam: &Pam) {
    if let Some(token) = pam.take().and_then(|kept| kept.for_user(&pam.item(PAM_USER))) {
        put(pam, &[(LOGIN, &token)]);
    }
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
