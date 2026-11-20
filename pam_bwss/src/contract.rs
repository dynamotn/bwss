//! The keyring entries pam_bwss leaves for the consumer (bwss, or the dybw
//! agent), and the pure decisions behind them. Nothing here touches the
//! system, so it is tested on every platform.
//!
//! Every entry is a key of type `user` in the user keyring (`@u`) of the user
//! who logs in, owned by that user, readable by them and by its possessors
//! only, and expiring after [`TIMEOUT_SECONDS`].

use std::ffi::CStr;

use zeroize::Zeroizing;

/// A login token, wiped when dropped.
pub type Token = Zeroizing<Vec<u8>>;

/// The kernel key type of every entry.
pub const KEY_TYPE: &CStr = c"user";
/// The login token, put at session open and after a password change.
pub const LOGIN: &CStr = c"dybw:login";
/// The token before a password change, put just before the new [`LOGIN`].
pub const LOGIN_OLD: &CStr = c"dybw:login-old";
/// A lock request, put at session close; its payload is no secret.
pub const LOCK: &CStr = c"dybw:lock";
/// Seconds before the kernel drops an entry the consumer did not take.
pub const TIMEOUT_SECONDS: u32 = 60;

const VIEW: u32 = 0x01;
const READ: u32 = 0x02;
const SEARCH: u32 = 0x08;
/// View, read and search for the possessor and the owning user; nothing for
/// group and other, and no write, link or setattr for anyone. Search lets the
/// consumer find the entry (`keyctl search @u user dybw:login`) and
/// invalidate it once read (`KEYCTL_INVALIDATE` needs only search).
pub const PERM: u32 = (VIEW | READ | SEARCH) << 24 | (VIEW | READ | SEARCH) << 16;

/// `PAM_UPDATE_AUTHTOK`: the phase of `pam_sm_chauthtok` that changes it.
pub const PAM_UPDATE_AUTHTOK: i32 = 0x2000;
/// `PAM_REINITIALIZE_CRED` and `PAM_REFRESH_CRED`: what a screen locker asks
/// of `pam_setcred` after it authenticated again.
pub const PAM_REINITIALIZE_CRED: i32 = 0x0008;
pub const PAM_REFRESH_CRED: i32 = 0x0010;

/// The copy `auth` keeps: the token, bound to the `PAM_USER` it was given for.
#[derive(Clone)]
pub struct Kept {
    user: Token,
    token: Token,
}

impl Kept {
    pub fn new(user: Token, token: Token) -> Self {
        Self { user, token }
    }

    /// The token, only for the user it was given for: a stack that changes
    /// `PAM_USER` after `auth` (`sudo -u`, `su`) never hands one user's
    /// password to another. Dropping the rest wipes it.
    pub fn for_user(self, user: &[u8]) -> Option<Token> {
        (self.user.as_slice() == user).then_some(self.token)
    }
}

/// Whether `pam_sm_setcred` hands the kept token over, as session open does:
/// for a screen locker's refresh, not for the `PAM_ESTABLISH_CRED` of a login
/// (its session open follows) nor for `PAM_DELETE_CRED`.
pub fn setcred_hands_over(flags: i32) -> bool {
    flags & (PAM_REINITIALIZE_CRED | PAM_REFRESH_CRED) != 0
}

/// A token worth handing over: an absent or empty one (a login without a
/// password) gives nothing.
pub fn nonempty(token: Token) -> Option<Token> {
    (!token.is_empty()).then_some(token)
}

/// The entries `pam_sm_chauthtok` puts, in order: nothing before the update
/// phase or without a new token; the old token first, when there is one (a
/// reset by root has none, and the consumer then fails to unwrap with the
/// new one, which invalidates the protector as ADR 0006 wants).
pub fn password_entries<'a>(flags: i32, old: &'a [u8], new: &'a [u8]) -> Vec<(&'static CStr, &'a [u8])> {
    if flags & PAM_UPDATE_AUTHTOK == 0 || new.is_empty() {
        return Vec::new();
    }
    [(LOGIN_OLD, old), (LOGIN, new)].into_iter().filter(|(_, token)| !token.is_empty()).collect()
}

/// The payload of [`LOCK`]: the closing session's `XDG_SESSION_ID` (set by
/// pam_systemd), or `-` when there is none (a user key cannot be empty).
pub fn lock_payload(session: &[u8]) -> &[u8] {
    if session.is_empty() { b"-" } else { session }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_token_gives_nothing() {
        assert_eq!(nonempty(Token::default()), None);
        assert_eq!(nonempty(Token::new(b"pw".to_vec())).as_deref().map(Vec::as_slice), Some(&b"pw"[..]));
    }

    #[test]
    fn a_kept_token_goes_to_its_own_user_only() {
        let kept = Kept::new(Token::new(b"alice".to_vec()), Token::new(b"pw".to_vec()));
        assert_eq!(kept.clone().for_user(b"alice").as_deref().map(Vec::as_slice), Some(&b"pw"[..]));
        assert!(kept.clone().for_user(b"bob").is_none(), "PAM_USER changed after auth");
        assert!(kept.for_user(b"").is_none());
    }

    #[test]
    fn only_a_refresh_of_credentials_hands_the_token_over() {
        assert!(setcred_hands_over(PAM_REFRESH_CRED));
        assert!(setcred_hands_over(PAM_REINITIALIZE_CRED | 0x8000), "PAM_SILENT does not matter");
        assert!(!setcred_hands_over(0x0002), "PAM_ESTABLISH_CRED: session open follows");
        assert!(!setcred_hands_over(0x0004), "PAM_DELETE_CRED");
    }

    #[test]
    fn the_entries_are_user_keys_readable_by_the_user_alone_for_a_minute() {
        assert_eq!(KEY_TYPE, c"user");
        assert_eq!((LOGIN, LOGIN_OLD, LOCK), (c"dybw:login", c"dybw:login-old", c"dybw:lock"));
        assert_eq!(TIMEOUT_SECONDS, 60);
        assert_eq!(PERM, 0x0b0b_0000, "possessor and user: view, read, search; group and other: none");
    }

    #[test]
    fn a_password_change_gives_the_old_token_then_the_new_one() {
        let update = PAM_UPDATE_AUTHTOK;
        assert_eq!(password_entries(update, b"old", b"new"), vec![(LOGIN_OLD, &b"old"[..]), (LOGIN, &b"new"[..])]);
        assert_eq!(
            password_entries(update, b"", b"new"),
            vec![(LOGIN, &b"new"[..])],
            "a reset by root has no old token"
        );
        assert!(password_entries(update, b"old", b"").is_empty(), "no new token, nothing");
        assert!(password_entries(0x4000, b"old", b"new").is_empty(), "the preliminary check gives nothing");
    }

    #[test]
    fn a_lock_request_names_the_session_or_none() {
        assert_eq!(lock_payload(b"3"), b"3");
        assert_eq!(lock_payload(b""), b"-");
    }
}
