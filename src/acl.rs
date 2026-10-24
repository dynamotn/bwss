//! Identifies the application behind a D-Bus call.
//!
//! The executable path is what the item ACL records. It is a speed bump, not
//! a sandbox: every process of the same user can still ptrace the daemon or
//! the client. It does stop one ordinary app from quietly reading another
//! app's secrets, which plain Secret Service implementations allow.

use std::path::{Path, PathBuf};

use zbus::{Connection, fdo::DBusProxy, message::Header, names::BusName};

pub const UNKNOWN: &str = "(unknown application)";

pub async fn caller_executable(conn: &Connection, header: &Header<'_>) -> String {
    let Some(sender) = header.sender() else { return UNKNOWN.into() };
    let Ok(proxy) = DBusProxy::new(conn).await else { return UNKNOWN.into() };
    let Ok(pid) = proxy.get_connection_unix_process_id(BusName::Unique(sender.to_owned())).await else {
        return UNKNOWN.into();
    };
    executable_of(pid).unwrap_or_else(|| UNKNOWN.into())
}

/// The executable of a process, from `/proc` (Linux only; `None` elsewhere).
pub fn executable_of(pid: u32) -> Option<String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(strip_deleted(&path.to_string_lossy()).to_owned())
}

/// `/proc/<pid>/exe` names a binary replaced on disk (an upgrade) "<path> (deleted)".
fn strip_deleted(path: &str) -> &str {
    path.strip_suffix(" (deleted)").unwrap_or(path)
}

/// Whether process `pid` was started as `<bwss> daemon [--replace]`, from
/// `/proc/<pid>/cmdline`. The executable alone is not enough: a squatter can
/// fork (the child keeps the bus connection) and exec bwss in the parent,
/// whose pid is the one the bus reports.
pub fn runs_daemon(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|raw| is_daemon_cmdline(&raw))
}

fn is_daemon_cmdline(raw: &[u8]) -> bool {
    let mut args = raw.strip_suffix(b"\0").unwrap_or(raw).split(|&b| b == 0).skip(1);
    args.next() == Some(b"daemon".as_slice()) && args.all(|a| a == b"--replace")
}

/// Whether `owner` (a path from `executable_of`) is the same binary as `me`
/// (`current_exe()`), comparing canonical paths where they still resolve.
pub fn same_executable(owner: &str, me: &Path) -> bool {
    let canonical = |p: &str| {
        let p = Path::new(strip_deleted(p));
        std::fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p))
    };
    canonical(owner) == canonical(&me.to_string_lossy())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn same_executable_sees_through_links_and_replaced_binaries() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bwss");
        std::fs::write(&bin, b"").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&bin, &link).unwrap();
        let bin_str = bin.to_str().unwrap();

        assert!(same_executable(bin_str, &bin));
        assert!(same_executable(link.to_str().unwrap(), &bin), "a symlink names the same file");
        // An upgraded binary shows as "(deleted)" in /proc, on either side.
        assert!(same_executable(&format!("{bin_str} (deleted)"), &bin));
        assert!(same_executable(bin_str, Path::new(&format!("{bin_str} (deleted)"))));

        let other = dir.path().join("python3");
        std::fs::write(&other, b"").unwrap();
        assert!(!same_executable(other.to_str().unwrap(), &bin));
        assert!(!same_executable("/nonexistent/bwss", &bin));
    }

    #[test]
    fn only_a_daemon_command_line_counts_as_the_daemon() {
        assert!(is_daemon_cmdline(b"/usr/bin/bwss\0daemon\0"));
        assert!(is_daemon_cmdline(b"bwss\0daemon\0--replace\0"));
        assert!(!is_daemon_cmdline(b"/usr/bin/bwss\0unlock\0"), "a blocking client is not the daemon");
        assert!(!is_daemon_cmdline(b"/usr/bin/bwss\0daemon\0--other\0"));
        assert!(!is_daemon_cmdline(b"/usr/bin/bwss\0--replace\0daemon\0"));
        assert!(!is_daemon_cmdline(b"/usr/bin/bwss\0"));
        assert!(!is_daemon_cmdline(b""));
        assert!(!runs_daemon(u32::MAX), "no such process");
    }
}
