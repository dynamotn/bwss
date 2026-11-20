//! pam_bwss — hands the Linux login password to the dybw consumer through
//! the user's kernel keyring (dybw ADR 0006, "The PAM module").
//!
//! It runs as root inside login, the display manager or the screen locker,
//! listed `optional` after pam_unix. It never prompts, never talks to D-Bus,
//! a socket or the network, runs no KDF, logs nothing and writes no file,
//! and every hook returns `PAM_IGNORE`: it never changes the outcome of a
//! login. The entries it leaves are described in [`contract`].
//!
//! Linux only: on other platforms the library holds `contract` alone.

pub mod contract;
// Unit tests cover `contract`; the entry points run under pamtester (tests/pam),
// and leaving them out of the test binary keeps their coverage records apart.
#[cfg(all(target_os = "linux", not(test)))]
#[allow(unsafe_code)]
mod ffi;
#[cfg(all(target_os = "linux", not(test)))]
mod hooks;
