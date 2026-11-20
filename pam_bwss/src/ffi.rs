//! The only unsafe code: the PAM entry points, libpam, and the kernel keyring
//! through raw `add_key`/`keyctl` syscalls. What the hooks decide lives in
//! `hooks` and `contract`.

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::mem::MaybeUninit;
use std::panic::{AssertUnwindSafe, catch_unwind, set_hook};
use std::ptr;
use std::sync::Once;
use std::thread::sleep;
use std::time::{Duration, Instant};

use libc::{SIGKILL, WNOHANG, gid_t, kill, uid_t, waitpid};

use crate::contract::{KEY_TYPE, Kept, PERM, TIMEOUT_SECONDS, Token};
use crate::hooks;

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
pub const PAM_USER: c_int = 2;
pub const PAM_AUTHTOK: c_int = 6;
pub const PAM_OLDAUTHTOK: c_int = 7;
/// The `pam_set_data` name of the copy `auth` keeps for `session` open.
const DATA: &CStr = c"pam_bwss_authtok";
/// How long the host waits for the keyring child before killing it.
const CHILD_DEADLINE: Duration = Duration::from_secs(2);

// The raw setxid syscalls below take 32-bit ids only on 64-bit targets.
#[cfg(not(target_pointer_width = "64"))]
compile_error!("pam_bwss supports 64-bit Linux only");

const KEY_SPEC_SESSION_KEYRING: c_long = -3;
const KEY_SPEC_USER_KEYRING: c_long = -4;
const KEYCTL_JOIN_SESSION_KEYRING: c_long = 1;
const KEYCTL_SETPERM: c_long = 5;
const KEYCTL_LINK: c_long = 8;
const KEYCTL_UNLINK: c_long = 9;
const KEYCTL_SEARCH: c_long = 10;
const KEYCTL_SET_TIMEOUT: c_long = 15;

#[repr(C)]
pub struct PamHandle {
    _opaque: [u8; 0],
}

type Cleanup = unsafe extern "C" fn(*mut PamHandle, *mut c_void, c_int);

// libpam is always loaded by the process that loads this module; naming the
// runtime library avoids needing its development package to build.
#[link(name = "libpam.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_set_data(pamh: *mut PamHandle, name: *const c_char, data: *mut c_void, cleanup: Option<Cleanup>) -> c_int;
    fn pam_get_data(pamh: *const PamHandle, name: *const c_char, data: *mut *const c_void) -> c_int;
    fn pam_getenv(pamh: *mut PamHandle, name: *const c_char) -> *const c_char;
}

/// The handle libpam passed to the entry point running now; only the entry
/// points below make one, so every method may trust it.
pub struct Pam(*mut PamHandle);

impl Pam {
    /// A string item (`PAM_USER`, `PAM_AUTHTOK`, …), copied; empty when unset.
    pub fn item(&self, which: c_int) -> Token {
        let mut item: *const c_void = ptr::null();
        // SAFETY: self.0 is libpam's live handle and `item` a valid out-pointer.
        let found = unsafe { pam_get_item(self.0, which, &mut item) } == PAM_SUCCESS && !item.is_null();
        // SAFETY: a string item is NUL-terminated and libpam keeps it alive for this call.
        Token::new(if found { unsafe { CStr::from_ptr(item.cast()) }.to_bytes().to_vec() } else { Vec::new() })
    }

    /// A variable of the PAM environment, copied; empty when unset.
    pub fn env(&self, name: &CStr) -> Vec<u8> {
        // SAFETY: self.0 is libpam's live handle and `name` a C string.
        let value = unsafe { pam_getenv(self.0, name.as_ptr()) };
        // SAFETY: a non-null value is a NUL-terminated string libpam keeps alive for this call.
        if value.is_null() { Vec::new() } else { unsafe { CStr::from_ptr(value) }.to_bytes().to_vec() }
    }

    /// Gives `kept` to libpam until `take` or `pam_end`; `wipe` frees it.
    pub fn keep(&self, kept: Kept) {
        let data = Box::into_raw(Box::new(kept));
        // SAFETY: libpam stores the pointer and later hands it to `wipe` once.
        let refused = unsafe { pam_set_data(self.0, DATA.as_ptr(), data.cast(), Some(wipe)) } != PAM_SUCCESS;
        // SAFETY: refused, so libpam never saw it and it is still ours to free (which wipes it).
        drop(refused.then(|| unsafe { Box::from_raw(data) }));
    }

    /// A copy of what `keep` stored, whose stored copy is wiped now.
    pub fn take(&self) -> Option<Kept> {
        let mut data: *const c_void = ptr::null();
        // SAFETY: self.0 is libpam's live handle and `data` a valid out-pointer.
        let found = unsafe { pam_get_data(self.0, DATA.as_ptr(), &mut data) } == PAM_SUCCESS && !data.is_null();
        if !found {
            return None;
        }
        // SAFETY: only `keep` sets DATA, to a live Box<Kept>, freed only below.
        let kept = unsafe { &*data.cast::<Kept>() }.clone();
        // SAFETY: replacing the data makes libpam call `wipe` on the stored copy.
        unsafe { pam_set_data(self.0, DATA.as_ptr(), ptr::null_mut(), None) };
        Some(kept)
    }
}

/// The `pam_set_data` cleanup: frees, and so zeroizes, the kept token.
unsafe extern "C" fn wipe(_pamh: *mut PamHandle, data: *mut c_void, _status: c_int) {
    // SAFETY: `data` is the Box<Kept> that `keep` handed to libpam, passed here once.
    drop((!data.is_null()).then(|| unsafe { Box::from_raw(data.cast::<Kept>()) }));
}

/// The uid and primary gid of the account `name`.
pub fn user(name: &[u8]) -> Option<(uid_t, gid_t)> {
    let name = CString::new(name).ok()?;
    let mut pw = MaybeUninit::<libc::passwd>::uninit();
    let mut buf = vec![0 as c_char; 16 * 1024];
    let mut out: *mut libc::passwd = ptr::null_mut();
    // SAFETY: every pointer is valid for the call, and `buf` is as long as stated.
    let rc = unsafe { libc::getpwnam_r(name.as_ptr(), pw.as_mut_ptr(), buf.as_mut_ptr(), buf.len(), &mut out) };
    // SAFETY: on success getpwnam_r filled `pw` (and pointed `out` at it).
    (rc == 0 && !out.is_null()).then(|| unsafe { pw.assume_init_ref() }).map(|pw| (pw.pw_uid, pw.pw_gid))
}

/// Writes `entries` into the user keyring of `uid`, from a forked child that
/// becomes that user: this process's credentials never change, even for a
/// moment, whatever other threads the host runs.
pub fn write_as(uid: uid_t, gid: gid_t, entries: &[(&CStr, &[u8])]) {
    // SAFETY: the child makes only syscalls on memory prepared before the fork,
    // then _exit. (glibc's `_Fork`, which skips atfork handlers, is not in libc.)
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // A panic in the child must never unwind back into the host's code.
        let _ = catch_unwind(AssertUnwindSafe(|| in_child(uid, gid, entries)));
        exit_child();
    }
    reap(pid);
}

/// Waits for the child at most CHILD_DEADLINE, so a child that is stopped
/// (SIGSTOP) or stuck never stalls a login; then kills and reaps it. A failed
/// fork (`pid` -1) has nothing to wait for.
fn reap(pid: libc::pid_t) {
    let deadline = Instant::now() + CHILD_DEADLINE;
    // SAFETY: a plain syscall on our own child; -1 (another reaper took it: ECHILD) also ends the wait.
    let running = || unsafe { waitpid(pid, ptr::null_mut(), WNOHANG) } == 0;
    let mut alive = pid > 0 && running();
    while alive && Instant::now() < deadline {
        sleep(Duration::from_millis(2));
        alive = running();
    }
    // SAFETY: plain syscalls on our own child, which is still running.
    let _ = alive && unsafe { kill(pid, SIGKILL) == 0 && waitpid(pid, ptr::null_mut(), 0) > 0 };
}

fn in_child(uid: uid_t, gid: gid_t, entries: &[(&CStr, &[u8])]) {
    // SAFETY: getuid is async-signal-safe.
    let same_user = unsafe { libc::getuid() } == uid;
    // Raw syscalls, not glibc's setxid wrappers (not async-signal-safe after a
    // fork). Groups are left alone only when already running as the user;
    // otherwise they must drop, and nothing is written unless all of it worked.
    let (uid_l, gid_l) = (c_long::from(uid), c_long::from(gid));
    let groups = same_user || (drop_groups() && setxid(libc::SYS_setresgid, gid_l, gid_l, gid_l));
    // SAFETY: getgid, getegid, getuid and geteuid are async-signal-safe.
    let ids = || unsafe { (libc::getgid(), libc::getegid(), libc::getuid(), libc::geteuid()) };
    let dropped = groups && setxid(libc::SYS_setresuid, uid_l, uid_l, uid_l) && {
        let (g, eg, u, eu) = ids();
        (same_user || (g == gid && eg == gid)) && u == uid && eu == uid
    };
    // A session keyring of the user's own makes each new key possessed, so its
    // timeout and permissions can be set; it goes with the child.
    if !dropped || keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0) < 0 {
        return;
    }
    for &(description, payload) in entries {
        put(description, payload);
    }
}

/// A raw `setresuid`/`setresgid` syscall; true on success.
fn setxid(nr: c_long, a: c_long, b: c_long, c: c_long) -> bool {
    // SAFETY: these syscalls take ids only and read no memory.
    unsafe { libc::syscall(nr, a, b, c) == 0 }
}

/// A raw `setgroups(0, NULL)`: no supplementary groups; true on success.
fn drop_groups() -> bool {
    // SAFETY: an empty list, so the kernel reads nothing through the null pointer.
    unsafe { libc::syscall(libc::SYS_setgroups, 0 as c_long, ptr::null::<gid_t>()) == 0 }
}

/// Replaces the entry `description` in `@u`. The key is born in the child's
/// session keyring and reaches `@u` only once it has its timeout, and before
/// it loses its link permission, so `@u` never holds a copy without a timeout.
fn put(description: &CStr, payload: &[u8]) {
    let (kind, name) = (KEY_TYPE.as_ptr() as c_long, description.as_ptr() as c_long);
    let old = keyctl(KEYCTL_SEARCH, KEY_SPEC_USER_KEYRING, kind, name);
    if old > 0 {
        keyctl(KEYCTL_UNLINK, old, KEY_SPEC_USER_KEYRING, 0);
    }
    // SAFETY: the type and description are C strings, the payload is valid for its length.
    let id = unsafe {
        libc::syscall(libc::SYS_add_key, kind, name, payload.as_ptr(), payload.len(), KEY_SPEC_SESSION_KEYRING)
    };
    let _ = id > 0
        && keyctl(KEYCTL_SET_TIMEOUT, id, c_long::from(TIMEOUT_SECONDS), 0) == 0
        && keyctl(KEYCTL_LINK, id, KEY_SPEC_USER_KEYRING, 0) == 0
        && keyctl(KEYCTL_SETPERM, id, c_long::from(PERM), 0) == 0;
}

/// `keyctl(cmd, a, b, c)` for the commands above, whose pointer arguments
/// are C strings only (none writes into this process's memory).
fn keyctl(cmd: c_long, a: c_long, b: c_long, c: c_long) -> c_long {
    // SAFETY: see above; the kernel checks every argument.
    unsafe { libc::syscall(libc::SYS_keyctl, cmd, a, b, c, 0 as c_long) }
}

/// Ends the child without the host's atexit handlers or stdio buffers.
fn exit_child() -> ! {
    #[cfg(coverage)]
    {
        unsafe extern "C" {
            fn __llvm_profile_write_file() -> c_int;
        }
        // SAFETY: the profiler runtime of coverage builds; it saves the counters _exit would drop.
        unsafe { __llvm_profile_write_file() };
    }
    // SAFETY: always safe to call; it does not return.
    unsafe { libc::_exit(0) }
}

/// Runs `hook` on the handle and returns `PAM_IGNORE`, whatever happens: a
/// panic must not unwind into libpam, and the module never decides a login.
fn entry(pamh: *mut PamHandle, hook: impl FnOnce(&Pam)) -> c_int {
    // This cdylib carries its own std, whose panic hook only its own panics
    // reach: silencing it once keeps them out of the host's log and touches no
    // hook of the host.
    static SILENT: Once = Once::new();
    SILENT.call_once(|| set_hook(Box::new(|_| {})));
    let _ = catch_unwind(AssertUnwindSafe(|| hook(&Pam(pamh))));
    PAM_IGNORE
}

/// # Safety
/// Called by libpam only, with a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _: c_int,
    _: c_int,
    _: *const *const c_char,
) -> c_int {
    entry(pamh, hooks::authenticate)
}

/// # Safety
/// Called by libpam only, with a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    pamh: *mut PamHandle,
    flags: c_int,
    _: c_int,
    _: *const *const c_char,
) -> c_int {
    entry(pamh, |pam| hooks::setcred(pam, flags))
}

/// # Safety
/// Called by libpam only, with a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _: c_int,
    _: c_int,
    _: *const *const c_char,
) -> c_int {
    entry(pamh, hooks::open_session)
}

/// # Safety
/// Called by libpam only, with a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_close_session(
    pamh: *mut PamHandle,
    _: c_int,
    _: c_int,
    _: *const *const c_char,
) -> c_int {
    entry(pamh, hooks::close_session)
}

/// # Safety
/// Called by libpam only, with a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_chauthtok(
    pamh: *mut PamHandle,
    flags: c_int,
    _: c_int,
    _: *const *const c_char,
) -> c_int {
    entry(pamh, |pam| hooks::chauthtok(pam, flags))
}
