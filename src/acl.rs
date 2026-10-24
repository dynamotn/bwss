//! Identifies the application behind a D-Bus call.
//!
//! The executable path is what the item ACL records. It is a speed bump, not
//! a sandbox: every process of the same user can still ptrace the daemon or
//! the client. It does stop one ordinary app from quietly reading another
//! app's secrets, which plain Secret Service implementations allow.
//!
//! An interpreter running a script file is identified as that script:
//! `<interpreter>/<script>` (see [`script_argument`]). Like the executable,
//! the command line is what the process says it is: a speed bump.
//!
//! A connection is pinned to the process first seen behind it: its pid, its
//! start time and its executable. The bus hands over a pidfd (`ProcessFD`)
//! where it can, which cannot be recycled; otherwise the pid is checked
//! against its start time. A later call from a process that no longer
//! matches that first sight (the pid was reused, or the process exec'd
//! another binary) is an unknown application.

use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};

use zbus::{Connection, fdo::DBusProxy, message::Header, names::BusName};

pub const UNKNOWN: &str = "(unknown application)";

/// What bwss can tell about a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerKind {
    /// No executable could be pinned to the connection.
    Unknown,
    /// A script interpreter with no script file bwss could resolve (`-c`,
    /// `-m`, stdin...): every such use shares its identity.
    Interpreter,
    /// An interpreter running a script file: `<interpreter>/<script>`.
    Script,
    /// An ordinary executable.
    App,
}

/// Basenames that run scripts: exact names, then prefixes (`python3.13`).
const INTERPRETERS: &[&str] =
    &["node", "nodejs", "deno", "bun", "sh", "bash", "zsh", "fish", "dash", "busybox", "java"];
const INTERPRETER_PREFIXES: &[&str] = &["python", "perl", "ruby", "lua", "php"];

/// Classifies a caller as `caller_executable` reported it.
pub fn kind(caller: &str) -> CallerKind {
    if !caller.starts_with('/') {
        return CallerKind::Unknown;
    }
    if let Some((interpreter, script)) = caller.split_once("//") {
        return if !script.is_empty() && is_interpreter(interpreter) {
            CallerKind::Script
        } else {
            CallerKind::Unknown
        };
    }
    if is_interpreter(caller) { CallerKind::Interpreter } else { CallerKind::App }
}

fn is_interpreter(exe: &str) -> bool {
    let base = exe.rsplit('/').next().unwrap_or_default();
    INTERPRETERS.contains(&base) || INTERPRETER_PREFIXES.iter().any(|p| base.starts_with(p))
}

/// The identity, and ACL line, of `interpreter` running `script`, both
/// canonical absolute paths: joined by one `/`, so the line holds the only
/// `//` (a canonical path never contains one).
fn script_identity(interpreter: &str, script: &str) -> String {
    format!("{interpreter}/{script}")
}

/// A caller for people: `<interpreter> running <script>` for a script.
pub fn describe(caller: &str) -> String {
    match (kind(caller), caller.split_once("//")) {
        (CallerKind::Script, Some((interpreter, script))) => format!("{interpreter} running /{script}"),
        _ => caller.to_owned(),
    }
}

/// Flags that take no value and keep the next argument the script.
const PLAIN_FLAGS: &[&str] = &["-u", "-B", "-I", "-O", "-OO", "-q", "-w", "-x", "-l"];

/// The script argument of an interpreter's command line (`/proc/<pid>/cmdline`):
/// the first argument after the interpreter that is not an option, after
/// `--`, or after flags from [`PLAIN_FLAGS`] only. Any other option (`-c`,
/// `-m`, `-e`, `-s`, `-`, one with a value) means there is no script file.
pub fn script_argument(cmdline: &[u8]) -> Option<String> {
    let raw = cmdline.strip_suffix(b"\0").unwrap_or(cmdline);
    let mut args = raw.split(|&b| b == 0).skip(1);
    let script = loop {
        let arg = std::str::from_utf8(args.next()?).ok()?;
        match arg {
            "--" => break std::str::from_utf8(args.next()?).ok()?,
            a if a.starts_with('-') && PLAIN_FLAGS.contains(&a) => continue,
            a if a.starts_with('-') => return None,
            a => break a,
        }
    };
    (!script.is_empty()).then(|| script.to_owned())
}

/// `arg` resolved against the caller's working directory `cwd`, canonical,
/// when it names an existing regular file.
pub fn resolve_script(cwd: &Path, arg: &str) -> Option<String> {
    let path = std::fs::canonicalize(cwd.join(arg)).ok()?;
    if !std::fs::metadata(&path).ok()?.is_file() {
        return None;
    }
    path.to_str().map(str::to_owned)
}

/// The script file interpreter process `pid` runs, if any.
fn script_of(pid: u32) -> Option<String> {
    let arg = script_argument(&std::fs::read(format!("/proc/{pid}/cmdline")).ok()?)?;
    resolve_script(Path::new(&format!("/proc/{pid}/cwd")), &arg)
}

/// Records what was `seen` behind a name that just appeared on the bus,
/// unless a call already pinned it.
pub fn first_sight(pins: &mut HashMap<String, Pin>, name: &str, seen: Option<Pin>) {
    if let Some(seen) = seen {
        pins.entry(name.to_owned()).or_insert(seen);
    }
}

/// A process as first seen behind a bus connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub pid: u32,
    /// Start time in clock ticks since boot (`/proc/<pid>/stat` field 22).
    pub start: u64,
    /// The executable, or `<interpreter>/<script>` (see [`kind`]).
    pub identity: String,
}

/// The processes pinned to the unique bus names that called so far.
#[derive(Default)]
pub struct Identities {
    pins: std::sync::Mutex<HashMap<String, Pin>>,
}

impl Identities {
    /// The executable behind the sender of `header`, or [`UNKNOWN`].
    pub async fn caller_executable(&self, conn: &Connection, header: &Header<'_>) -> String {
        let Some(sender) = header.sender() else { return UNKNOWN.into() };
        let seen = match DBusProxy::new(conn).await {
            Ok(proxy) => look_up(&proxy, BusName::Unique(sender.to_owned())).await,
            Err(_) => None,
        };
        settle(&mut crate::sync::lock(&self.pins), sender.as_str(), seen)
    }

    /// Pins a unique name as soon as it appears on the bus, so that the pid
    /// cannot be reused before its first call.
    pub async fn appeared(&self, conn: &Connection, name: &str) {
        let Ok(unique) = zbus::names::UniqueName::try_from(name) else { return };
        let seen = match DBusProxy::new(conn).await {
            Ok(proxy) => look_up(&proxy, BusName::Unique(unique)).await,
            Err(_) => None,
        };
        first_sight(&mut crate::sync::lock(&self.pins), name, seen);
    }

    /// The names pinned so far.
    pub fn names(&self) -> Vec<String> {
        crate::sync::lock(&self.pins).keys().cloned().collect()
    }

    /// Forgets a name that left the bus.
    pub fn forget(&self, name: &str) {
        crate::sync::lock(&self.pins).remove(name);
    }
}

/// Reads the process behind `name` now, through its pidfd when the bus
/// provides one.
async fn look_up(proxy: &DBusProxy<'_>, name: BusName<'_>) -> Option<Pin> {
    match proxy.get_connection_credentials(name.clone()).await {
        Ok(creds) => {
            let pidfd = creds.process_fd().map(AsFd::as_fd);
            tracing::debug!(caller = %name, pidfd = pidfd.is_some(), "resolving the caller");
            observe(creds.process_id(), pidfd)
        }
        Err(_) => observe(proxy.get_connection_unix_process_id(name).await.ok(), None),
    }
}

/// Reads pid, start time and executable of a process. With a pidfd, the pid
/// comes from it and must still name the same live process after the reads,
/// so they are about that process and no other.
fn observe(pid: Option<u32>, pidfd: Option<BorrowedFd<'_>>) -> Option<Pin> {
    let pid = match pidfd {
        Some(fd) => {
            let from_fd = pidfd_pid(fd)?;
            if pid.is_some_and(|p| p != from_fd) {
                return None;
            }
            from_fd
        }
        None => pid?,
    };
    let start = start_time(pid)?;
    let exe = executable_of(pid)?;
    // An interpreter running a script file is that script.
    let identity = match is_interpreter(&exe).then(|| script_of(pid)).flatten() {
        Some(script) => script_identity(&exe, &script),
        None => exe,
    };
    if pidfd.is_some_and(|fd| pidfd_pid(fd) != Some(pid)) || start_time(pid) != Some(start) {
        return None;
    }
    Some(Pin { pid, start, identity })
}

/// The identity of `name` given what was `seen` now: the first sight is
/// recorded, and any later difference from it makes the caller unknown.
pub fn settle(pins: &mut HashMap<String, Pin>, name: &str, seen: Option<Pin>) -> String {
    let Some(seen) = seen else { return UNKNOWN.into() };
    match pins.get(name) {
        Some(first) if *first == seen => seen.identity,
        Some(_) => UNKNOWN.into(),
        None => {
            let identity = seen.identity.clone();
            pins.insert(name.to_owned(), seen);
            identity
        }
    }
}

/// Start time of process `pid` (Linux only; `None` elsewhere).
fn start_time(pid: u32) -> Option<u64> {
    parse_start_time(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Field 22 of `/proc/<pid>/stat`. The command name (field 2) may hold
/// spaces and parentheses, so fields are counted from its last `)`.
fn parse_start_time(stat: &str) -> Option<u64> {
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// The pid a pidfd refers to, from `/proc/self/fdinfo`; `None` once the
/// process is gone or when it is outside this pid namespace.
fn pidfd_pid(fd: BorrowedFd<'_>) -> Option<u32> {
    parse_pidfd_pid(&std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()?)
}

fn parse_pidfd_pid(fdinfo: &str) -> Option<u32> {
    let value = fdinfo.lines().find_map(|l| l.strip_prefix("Pid:"))?;
    value.trim().parse::<u32>().ok().filter(|&p| p > 0)
}

/// Whether `caller` runs this very executable: only the bwss CLI may send a
/// master password over the bus (`Control1.UnlockWithPassword`).
pub fn is_own_executable(caller: &str) -> bool {
    kind(caller) == CallerKind::App && std::env::current_exe().is_ok_and(|me| same_executable(caller, &me))
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

    #[test]
    fn interpreters_and_unknown_callers_are_told_apart() {
        for exe in [
            "/usr/bin/python3",
            "/usr/bin/python3.13",
            "/usr/bin/perl5.40",
            "/usr/bin/ruby3.3",
            "/usr/bin/node",
            "/usr/bin/deno",
            "/home/u/.bun/bin/bun",
            "/bin/sh",
            "/usr/bin/bash",
            "/usr/bin/zsh",
            "/usr/bin/fish",
            "/bin/dash",
            "/usr/bin/lua5.4",
            "/usr/bin/luajit",
            "/usr/bin/php8.2",
            "/usr/lib/jvm/bin/java",
            "/usr/bin/nodejs",
            "/bin/busybox",
        ] {
            assert_eq!(kind(exe), CallerKind::Interpreter, "{exe}");
        }
        for exe in ["/usr/bin/git", "/usr/bin/secret-tool", "/usr/bin/nodejs-tool", "/usr/bin/shotwell", "/opt/javac"] {
            assert_eq!(kind(exe), CallerKind::App, "{exe}");
        }
        assert_eq!(kind(UNKNOWN), CallerKind::Unknown);
        assert_eq!(kind(""), CallerKind::Unknown);
        assert_eq!(kind("python3"), CallerKind::Unknown, "only an absolute path names an executable");
        assert_eq!(kind("/usr/bin/python3//home/u/tool.py"), CallerKind::Script);
        assert_eq!(kind("/usr/bin/git//home/u/tool.py"), CallerKind::Unknown, "only an interpreter runs a script");
        assert_eq!(kind("/usr/bin/python3//"), CallerKind::Unknown);
    }

    #[test]
    fn the_script_is_the_first_plain_argument_after_known_flags() {
        let arg = |raw: &[u8]| script_argument(raw);
        assert_eq!(arg(b"python3\0/home/u/tool.py\0--flag\0"), Some("/home/u/tool.py".into()));
        assert_eq!(arg(b"python3\0-u\0-B\0tool.py\0"), Some("tool.py".into()));
        assert_eq!(arg(b"bash\0--\0-odd-name.sh\0"), Some("-odd-name.sh".into()));
        assert_eq!(arg(b"python3\0-c\0print(1)\0"), None, "code on the command line");
        assert_eq!(arg(b"python3\0-m\0http.server\0"), None, "a module");
        assert_eq!(arg(b"perl\0-e\0print 1\0"), None);
        assert_eq!(arg(b"python3\0-\0"), None, "stdin");
        assert_eq!(arg(b"sh\0-s\0/home/u/trusted.sh\0"), None, "sh -s reads stdin, the rest are arguments");
        assert_eq!(arg(b"python3\0-W\0/home/u/trusted.py\0evil.py\0"), None, "an option with a value");
        assert_eq!(arg(b"python3\0"), None, "interactive");
        assert_eq!(arg(b"python3\0\0"), None);
        assert_eq!(arg(b""), None);
    }

    #[test]
    fn a_script_resolves_to_an_existing_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(cwd.join("tool.py"), b"").unwrap();
        std::fs::create_dir(cwd.join("pkg")).unwrap();
        std::os::unix::fs::symlink(cwd.join("tool.py"), cwd.join("link.py")).unwrap();
        let expected = cwd.join("tool.py").to_str().unwrap().to_owned();
        assert_eq!(resolve_script(&cwd, "tool.py"), Some(expected.clone()), "relative to the caller's cwd");
        assert_eq!(resolve_script(&cwd, "./pkg/../link.py"), Some(expected.clone()), "canonical");
        assert_eq!(resolve_script(Path::new("/nonexistent"), &expected), Some(expected), "absolute");
        assert_eq!(resolve_script(&cwd, "pkg"), None, "a directory is no script");
        assert_eq!(resolve_script(&cwd, "missing.py"), None);
    }

    #[test]
    fn script_identities_read_as_interpreter_running_script() {
        assert_eq!(describe("/usr/bin/python3//home/u/tool.py"), "/usr/bin/python3 running /home/u/tool.py");
        assert_eq!(describe("/usr/bin/git"), "/usr/bin/git");
        assert_eq!(describe(UNKNOWN), UNKNOWN);
    }

    #[test]
    fn a_name_seen_appearing_is_pinned_before_its_first_call() {
        let pin = |start| Pin { pid: 10, start, identity: "/usr/bin/git".into() };
        let mut pins = std::collections::HashMap::new();
        first_sight(&mut pins, ":1.7", Some(pin(100)));
        // The pid was reused before the first call.
        assert_eq!(settle(&mut pins, ":1.7", Some(pin(200))), UNKNOWN);
        // A call that came first is not overridden by the late signal.
        assert_eq!(settle(&mut pins, ":1.8", Some(pin(300))), "/usr/bin/git");
        first_sight(&mut pins, ":1.8", Some(pin(400)));
        assert_eq!(settle(&mut pins, ":1.8", Some(pin(300))), "/usr/bin/git");
        first_sight(&mut pins, ":1.9", None);
        assert!(!pins.contains_key(":1.9"));
    }

    #[test]
    fn start_time_is_field_22_even_with_odd_command_names() {
        let stat = "4242 (a) b (c) S 1 4242 4242 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 987654 0 0";
        assert_eq!(parse_start_time(stat), Some(987_654));
        assert_eq!(parse_start_time("4242 (x) S 1"), None);
        assert_eq!(parse_start_time("garbage"), None);
    }

    #[test]
    fn a_pidfd_names_a_live_visible_process_only() {
        assert_eq!(parse_pidfd_pid("pos:\t0\nflags:\t02000002\nmnt_id:\t15\nPid:\t1234\nNSpid:\t1234\n"), Some(1234));
        assert_eq!(parse_pidfd_pid("Pid:\t-1\n"), None, "the process is gone");
        assert_eq!(parse_pidfd_pid("Pid:\t0\n"), None, "in another pid namespace");
        assert_eq!(parse_pidfd_pid("pos:\t0\n"), None, "not a pidfd");
    }

    #[test]
    fn a_connection_keeps_the_process_it_was_first_seen_with() {
        let pin = |pid, start, exe: &str| Pin { pid, start, identity: exe.into() };
        let mut pins = std::collections::HashMap::new();
        assert_eq!(settle(&mut pins, ":1.5", Some(pin(10, 100, "/usr/bin/git"))), "/usr/bin/git");
        assert_eq!(settle(&mut pins, ":1.5", Some(pin(10, 100, "/usr/bin/git"))), "/usr/bin/git");
        // The pid was reused by another process: same pid, new start time.
        assert_eq!(settle(&mut pins, ":1.5", Some(pin(10, 200, "/usr/bin/git"))), UNKNOWN);
        // The first process exec'd another binary after its first call.
        assert_eq!(settle(&mut pins, ":1.5", Some(pin(10, 100, "/usr/bin/ssh"))), UNKNOWN);
        // A mismatch never replaces the first sight.
        assert_eq!(settle(&mut pins, ":1.5", Some(pin(10, 100, "/usr/bin/git"))), "/usr/bin/git");
        assert_eq!(settle(&mut pins, ":1.5", None), UNKNOWN, "nothing could be read");
        assert_eq!(settle(&mut pins, ":1.6", None), UNKNOWN);
        assert!(!pins.contains_key(":1.6"), "an unreadable caller pins nothing");
        assert_eq!(settle(&mut pins, ":1.6", Some(pin(11, 1, "/usr/bin/ssh"))), "/usr/bin/ssh");
    }

    #[test]
    fn only_this_executable_may_send_a_password() {
        let me = std::env::current_exe().unwrap();
        assert!(is_own_executable(me.to_str().unwrap()));
        assert!(!is_own_executable("/usr/bin/python3"));
        assert!(!is_own_executable(UNKNOWN));
        assert!(!is_own_executable(&format!("/usr/bin/python3/{}", me.to_str().unwrap())));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_reads_back_through_proc() {
        let me = std::process::id();
        let start = start_time(me).unwrap();
        assert_eq!(start_time(me), Some(start), "a start time is stable");
        let seen = observe(Some(me), None).unwrap();
        assert_eq!(seen, Pin { pid: me, start, identity: executable_of(me).unwrap() });
        assert_eq!(observe(Some(me.wrapping_add(1 << 30)), None), None, "no such process");
        assert_eq!(observe(None, None), None);
    }
}
