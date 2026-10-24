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
use std::ffi::OsStr;
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
    // ACL lines are joined by newlines: a control character could plant one.
    if !caller.starts_with('/') || caller.chars().any(char::is_control) {
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

/// How bwss reads an interpreter's command line.
struct Family {
    /// Flags that take no value, so the next argument may still be the script.
    plain: &'static [&'static str],
    /// Whether `--` ends the options and the next argument is the script.
    dash_dash: bool,
}

/// The [`Family`] of the interpreter `base`; `None` when bwss does not
/// identify its scripts at all (subcommands, applets, `-jar`). A flag that is
/// plain in one interpreter takes a value in another (`ruby -I dir`,
/// `lua -l mod`), so every family has its own short list. `--` is honoured
/// only where it means "the script follows" (`php --` reads stdin).
fn family(base: &str) -> Option<Family> {
    const PYTHON: &[&str] = &["-u", "-B", "-I", "-O", "-OO", "-q", "-s", "-S", "-E"];
    const PERL: &[&str] = &["-w", "-W", "-X", "-T", "-t"];
    const RUBY: &[&str] = &["-w"];
    const SHELL: &[&str] = &["-e", "-u", "-x", "-v"];
    const NONE: &[&str] = &[];
    let (plain, dash_dash) = match base {
        "sh" | "bash" | "zsh" | "dash" => (SHELL, true),
        "node" | "nodejs" => (NONE, true),
        "fish" => (NONE, false),
        "deno" | "bun" | "busybox" | "java" => return None,
        b if b.starts_with("python") => (PYTHON, true),
        b if b.starts_with("perl") => (PERL, true),
        b if b.starts_with("ruby") => (RUBY, true),
        b if b.starts_with("lua") || b.starts_with("php") => (NONE, false),
        _ => return None,
    };
    Some(Family { plain, dash_dash })
}

/// The script argument of `interpreter`'s command line (`/proc/<pid>/cmdline`).
/// Every argument before it must be a value-less flag of that interpreter's
/// [`Family`], or a `--` the family honours. Anything else before it (`-c`,
/// `-m`, `-e`, `-s`, `-`, `+e`, an option with a value, an unknown flag), or
/// a candidate that is `-` (stdin, even after `--`) or starts with `+` (or
/// with `-`, unless after `--`), means there is no script file.
pub fn script_argument(interpreter: &str, cmdline: &[u8]) -> Option<String> {
    let family = family(interpreter.rsplit('/').next().unwrap_or_default())?;
    let raw = cmdline.strip_suffix(b"\0").unwrap_or(cmdline);
    let mut args = raw.split(|&b| b == 0).skip(1);
    let script = loop {
        let arg = std::str::from_utf8(args.next()?).ok()?;
        if family.plain.contains(&arg) {
            continue;
        }
        if arg == "--" && family.dash_dash {
            let next = std::str::from_utf8(args.next()?).ok()?;
            // Even after `--`, `-` is stdin to most interpreters and a `+`
            // name is an option to some shells.
            break if next == "-" || next.starts_with('+') { return None } else { next };
        }
        if arg.starts_with(['-', '+']) {
            return None;
        }
        break arg;
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
    let arg = script_argument(&executable_of(pid)?, &std::fs::read(format!("/proc/{pid}/cmdline")).ok()?)?;
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

/// What reading a pidfd's `/proc/self/fdinfo` gave.
#[derive(Debug, PartialEq)]
enum FdPid {
    Pid(u32),
    /// The process is gone, or outside this pid namespace.
    Gone,
    /// The file cannot be read (a non-dumpable daemon has a root-owned
    /// `/proc/self`, and kernels before 5.17-5.19 refuse `fdinfo` then).
    Unreadable,
}

/// How to resolve a caller, given its pidfd and the `ProcessID` the bus sent.
#[derive(Debug, PartialEq)]
enum Resolution {
    /// Read this pid, and check after the reads that the pidfd still names it.
    ByPidfd(u32),
    /// Read this pid, checking the start time only (no usable pidfd).
    ByPid(u32),
    Unknown,
}

fn resolve(pidfd: Option<FdPid>, bus_pid: Option<u32>) -> Resolution {
    match pidfd {
        Some(FdPid::Pid(from_fd)) if bus_pid.is_none_or(|p| p == from_fd) => Resolution::ByPidfd(from_fd),
        Some(FdPid::Pid(_) | FdPid::Gone) => Resolution::Unknown,
        // The same path as for a bus without `ProcessFD`.
        Some(FdPid::Unreadable) | None => bus_pid.map_or(Resolution::Unknown, Resolution::ByPid),
    }
}

/// Reads pid, start time and executable of a process. With a pidfd, the pid
/// comes from it and must still name the same live process after the reads,
/// so they are about that process and no other. When the pidfd cannot be
/// read, it falls back to `ProcessID` and the start time.
fn observe(pid: Option<u32>, pidfd: Option<BorrowedFd<'_>>) -> Option<Pin> {
    let fd_pid = pidfd.map(pidfd_pid);
    let resolution = resolve(fd_pid, pid);
    tracing::debug!(?resolution, "resolved the caller");
    let (pid, pidfd) = match resolution {
        Resolution::ByPidfd(pid) => (pid, pidfd),
        Resolution::ByPid(pid) => (pid, None),
        Resolution::Unknown => return None,
    };
    let start = start_time(pid)?;
    let exe = executable_of(pid)?;
    // An interpreter running a script file is that script.
    let identity = match is_interpreter(&exe).then(|| script_of(pid)).flatten() {
        Some(script) => script_identity(&exe, &script),
        None => exe,
    };
    if pidfd.is_some_and(|fd| pidfd_pid(fd) != FdPid::Pid(pid)) || start_time(pid) != Some(start) {
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

/// The pid a pidfd refers to, from `/proc/self/fdinfo`.
fn pidfd_pid(fd: BorrowedFd<'_>) -> FdPid {
    match std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())) {
        Ok(info) => parse_pidfd_pid(&info).map_or(FdPid::Gone, FdPid::Pid),
        Err(_) => FdPid::Unreadable,
    }
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

/// Whether a `/proc/<pid>/cmdline` reads `<bwss> daemon [--replace]`. The
/// executable alone is not enough: a squatter can fork (the child keeps the
/// bus connection) and exec bwss in the parent, whose pid the bus reports.
fn is_daemon_cmdline(raw: &[u8]) -> bool {
    let mut args = raw.strip_suffix(b"\0").unwrap_or(raw).split(|&b| b == 0).skip(1);
    args.next() == Some(b"daemon".as_slice()) && args.all(|a| a == b"--replace")
}

/// Checks that `pid` is a `bwss daemon` of this user running this binary,
/// without `/proc/<pid>/exe`: the daemon is not dumpable (TM-013), so only
/// its command line, status and start time are readable. Weaker than the
/// executable against `argv[0]` spoofing; a same-user fork and exec of the
/// real binary beats any pid check anyway. The start time is read before
/// and after, so a pid reused meanwhile is caught. `Err` says what failed.
pub fn check_daemon_owner(pid: u32, me: &Path, my_uid: u32) -> Result<(), String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    check_owner_with(pid, me, my_uid, &path, &|pid, file| std::fs::read(format!("/proc/{pid}/{file}")))
}

/// [`check_daemon_owner`] over a reader of `/proc/<pid>/<file>`.
fn check_owner_with(
    pid: u32,
    me: &Path,
    my_uid: u32,
    path_env: &OsStr,
    read: &dyn Fn(u32, &str) -> std::io::Result<Vec<u8>>,
) -> Result<(), String> {
    let start = || read(pid, "stat").ok().and_then(|raw| parse_start_time(&String::from_utf8_lossy(&raw)));
    let first = start().ok_or("whose start time cannot be read (it may have exited)")?;
    let status = read(pid, "status").map_err(|_| "whose /proc status cannot be read (it may have exited)")?;
    let cmdline = read(pid, "cmdline").unwrap_or_default();
    if cmdline.is_empty() {
        return Err("whose command line cannot be read or is empty (it may have exited)".into());
    }
    judge_daemon(parse_uid(&String::from_utf8_lossy(&status)), &cmdline, me, my_uid, path_env)?;
    if start() != Some(first) {
        return Err("whose start time changed during the check (the pid was reused?)".into());
    }
    Ok(())
}

fn judge_daemon(uid: Option<u32>, cmdline: &[u8], me: &Path, my_uid: u32, path_env: &OsStr) -> Result<(), String> {
    if uid != Some(my_uid) {
        let who = uid.map_or_else(|| "unknown".to_owned(), |u| u.to_string());
        return Err(format!("which belongs to another user (uid {who}, not {my_uid})"));
    }
    let argv0 = cmdline.split(|&b| b == 0).next().map(|a| String::from_utf8_lossy(a).into_owned()).unwrap_or_default();
    let resolved = if argv0.contains('/') {
        argv0.clone()
    } else {
        std::env::split_paths(path_env)
            .map(|dir| dir.join(&argv0))
            .find(|candidate| !argv0.is_empty() && candidate.is_file())
            .map_or_else(|| argv0.clone(), |found| found.to_string_lossy().into_owned())
    };
    if !same_executable(&resolved, me) {
        return Err(format!("which runs `{argv0}`, not this bwss ({})", me.display()));
    }
    if !is_daemon_cmdline(cmdline) {
        return Err("which is not a `bwss daemon`".into());
    }
    Ok(())
}

/// The real user id from the text of `/proc/<pid>/status`.
fn parse_uid(status: &str) -> Option<u32> {
    status.lines().find_map(|l| l.strip_prefix("Uid:"))?.split_whitespace().next()?.parse().ok()
}

/// Whether `owner` (a path such as `executable_of` returns) is the same binary as `me`
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
    }

    #[test]
    fn the_daemon_owner_is_judged_by_user_and_command_line() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bwss");
        std::fs::write(&bin, b"").unwrap();
        let other = dir.path().join("python3");
        std::fs::write(&other, b"").unwrap();
        let bin_s = bin.to_str().unwrap();
        let judge = |uid, cmd: &[u8], path: &OsStr| judge_daemon(uid, cmd, &bin, 1000, path);
        let cmd = |argv0: &str, rest: &str| format!("{argv0}\0{rest}").into_bytes();
        let none = OsStr::new("");

        assert_eq!(judge(Some(1000), &cmd(bin_s, "daemon\0--replace\0"), none), Ok(()));
        let err = judge(Some(1001), &cmd(bin_s, "daemon\0"), none).unwrap_err();
        assert!(err.contains("another user") && err.contains("1001"), "{err}");
        assert!(judge(None, &cmd(bin_s, "daemon\0"), none).unwrap_err().contains("unknown"));
        let err = judge(Some(1000), &cmd(other.to_str().unwrap(), "daemon\0"), none).unwrap_err();
        assert!(err.contains("not this bwss") && err.contains("python3"), "{err}");
        let err = judge(Some(1000), &cmd("bwss-fake", "daemon\0"), none).unwrap_err();
        assert!(err.contains("not this bwss"), "a bare name that resolves nowhere: {err}");
        assert!(judge(Some(1000), b"", none).unwrap_err().contains("not this bwss"));
        let err = judge(Some(1000), &cmd(bin_s, "unlock\0"), none).unwrap_err();
        assert!(err.contains("not a `bwss daemon`"), "{err}");
        // A bare argv[0] is looked up in PATH, the way the daemon was started.
        assert_eq!(judge(Some(1000), &cmd("bwss", "daemon\0"), dir.path().as_os_str()), Ok(()));
        let elsewhere = tempfile::tempdir().unwrap();
        assert!(judge(Some(1000), &cmd("bwss", "daemon\0"), elsewhere.path().as_os_str()).is_err());
    }

    fn proc_files<'a>(
        stat: &'a [&'a str],
        status: Option<&'a str>,
        cmdline: &'a [u8],
    ) -> impl Fn(u32, &str) -> std::io::Result<Vec<u8>> + 'a {
        let reads = std::cell::Cell::new(0);
        move |_, file| match file {
            "stat" => {
                let n = reads.get();
                reads.set(n + 1);
                stat.get(n).map(|s| s.as_bytes().to_vec()).ok_or_else(|| std::io::ErrorKind::NotFound.into())
            }
            "status" => {
                status.map(|s| s.as_bytes().to_vec()).ok_or_else(|| std::io::ErrorKind::PermissionDenied.into())
            }
            _ => Ok(cmdline.to_vec()),
        }
    }

    #[test]
    fn the_owner_check_reports_what_it_cannot_read_and_a_reused_pid() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bwss");
        std::fs::write(&bin, b"").unwrap();
        let cmd = format!("{}\0daemon\0", bin.display()).into_bytes();
        let stat = |start: u32| format!("1 (bwss) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0");
        let (a, b) = (stat(100), stat(200));
        let status = Some("Uid:\t1000\t1000\t1000\t1000\n");
        let check = |read: &dyn Fn(u32, &str) -> std::io::Result<Vec<u8>>| {
            check_owner_with(5, &bin, 1000, OsStr::new(""), read)
        };

        assert_eq!(check(&proc_files(&[&a, &a], status, &cmd)), Ok(()));
        let err = check(&proc_files(&[&a, &b], status, &cmd)).unwrap_err();
        assert!(err.contains("start time changed"), "{err}");
        let err = check(&proc_files(&[], status, &cmd)).unwrap_err();
        assert!(err.contains("start time cannot be read"), "{err}");
        let err = check(&proc_files(&[&a, &a], None, &cmd)).unwrap_err();
        assert!(err.contains("status cannot be read") && !err.contains("another user"), "{err}");
        let err = check(&proc_files(&[&a, &a], status, b"")).unwrap_err();
        assert!(err.contains("command line cannot be read or is empty"), "{err}");
        let err = check_daemon_owner(u32::MAX, &bin, 1000).unwrap_err();
        assert!(err.contains("start time cannot be read"), "{err}");
    }

    #[test]
    fn the_real_user_comes_from_proc_status() {
        assert_eq!(parse_uid("Name:\tbwss\nUid:\t1000\t1000\t1000\t1000\nGid:\t1\n"), Some(1000));
        assert_eq!(parse_uid("Name:\tbwss\n"), None);
        assert_eq!(parse_uid("Uid:\tx\n"), None);
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
        let py = |raw: &[u8]| script_argument("/usr/bin/python3.13", raw);
        assert_eq!(py(b"python3\0/home/u/tool.py\0--flag\0"), Some("/home/u/tool.py".into()));
        assert_eq!(py(b"python3\0-u\0-B\0-I\0tool.py\0"), Some("tool.py".into()));
        assert_eq!(py(b"python3\0--\0-odd-name.py\0"), Some("-odd-name.py".into()));
        assert_eq!(py(b"python3\0-c\0print(1)\0"), None, "code on the command line");
        assert_eq!(py(b"python3\0-m\0http.server\0"), None, "a module");
        assert_eq!(py(b"python3\0-\0"), None, "stdin");
        assert_eq!(py(b"python3\0-W\0/home/u/trusted.py\0evil.py\0"), None, "an option with a value");
        assert_eq!(py(b"python3\0-X\0dev\0tool.py\0"), None);
        assert_eq!(py(b"python3\0"), None, "interactive");
        assert_eq!(py(b"python3\0\0"), None);
        assert_eq!(py(b""), None);
    }

    #[test]
    fn flags_are_judged_per_interpreter_family() {
        let arg = script_argument;
        // Flags that are plain in python take a value elsewhere.
        assert_eq!(arg("/usr/bin/ruby3.3", b"ruby\0-I\0/tmp/trusted.rb\0evil.rb\0"), None);
        assert_eq!(arg("/usr/bin/lua5.4", b"lua\0-l\0/tmp/x\0script.lua\0"), None);
        assert_eq!(arg("/usr/bin/perl", b"perl\0-I\0/tmp/lib\0script.pl\0"), None);
        assert_eq!(arg("/usr/bin/perl", b"perl\0-x\0/tmp/dir\0script.pl\0"), None);
        assert_eq!(arg("/usr/bin/perl", b"perl\0-e\0print 1\0"), None);
        assert_eq!(arg("/usr/bin/perl", b"perl\0-w\0script.pl\0"), Some("script.pl".into()));
        assert_eq!(arg("/usr/bin/ruby3.3", b"ruby\0-w\0script.rb\0"), Some("script.rb".into()));
        assert_eq!(arg("/usr/bin/node", b"node\0-r\0/tmp/trusted.js\0evil.js\0"), None);
        assert_eq!(arg("/usr/bin/node", b"node\0app.js\0"), Some("app.js".into()));
        assert_eq!(arg("/usr/bin/bash", b"bash\0-e\0-x\0job.sh\0"), Some("job.sh".into()));
        assert_eq!(arg("/usr/bin/bash", b"bash\0-o\0/tmp/trusted.sh\0evil.sh\0"), None);
        assert_eq!(arg("/bin/sh", b"sh\0-s\0/home/u/trusted.sh\0"), None, "sh -s reads stdin");
        assert_eq!(arg("/bin/sh", b"sh\0-c\0echo\0"), None);
        // No script identity at all: subcommands or launchers.
        assert_eq!(arg("/usr/bin/deno", b"deno\0run\0x.ts\0"), None);
        assert_eq!(arg("/usr/bin/bun", b"bun\0x.ts\0"), None);
        assert_eq!(arg("/bin/busybox", b"busybox\0sh\0x.sh\0"), None);
        assert_eq!(arg("/usr/lib/jvm/bin/java", b"java\0-jar\0x.jar\0"), None);
        assert_eq!(arg("/usr/bin/git", b"git\0x\0"), None, "not an interpreter");
    }

    #[test]
    fn plus_options_and_unknown_arguments_mean_no_script() {
        let arg = script_argument;
        // `ln -s trusted.sh ./+e; bash +e evil.sh` must not pass for trusted.sh.
        assert_eq!(arg("/usr/bin/bash", b"bash\0+e\0evil.sh\0"), None);
        assert_eq!(arg("/usr/bin/bash", b"bash\0+O\0extglob\0evil.sh\0"), None);
        assert_eq!(arg("/usr/bin/zsh", b"zsh\0+e\0evil.sh\0"), None);
        assert_eq!(arg("/bin/dash", b"dash\0+e\0evil.sh\0"), None);
        assert_eq!(arg("/usr/bin/python3", b"python3\0+x\0"), None, "a script name starting with +");
        // `--` means "script follows" only where that is so.
        assert_eq!(arg("/usr/bin/php8.2", b"php\0--\0/home/u/trusted.php\0"), None, "php -- reads stdin");
        assert_eq!(arg("/usr/bin/php8.2", b"php\0tool.php\0"), Some("tool.php".into()));
        assert_eq!(arg("/usr/bin/bash", b"bash\0--\0job.sh\0"), Some("job.sh".into()));
        assert_eq!(arg("/usr/bin/fish", b"fish\0--\0job.fish\0"), None);
        assert_eq!(arg("/usr/bin/lua5.4", b"lua\0--\0s.lua\0"), None);
    }

    #[test]
    fn a_bare_dash_is_stdin_never_a_script() {
        // `ln -s trusted.py ./-; echo evil | python3 -- -` runs stdin.
        for (exe, argv0) in [
            ("/usr/bin/python3", "python3"),
            ("/usr/bin/perl", "perl"),
            ("/usr/bin/ruby3.3", "ruby"),
            ("/usr/bin/node", "node"),
            ("/usr/bin/bash", "bash"),
        ] {
            let after = format!("{argv0}\0--\0-\0");
            assert_eq!(script_argument(exe, after.as_bytes()), None, "{argv0} -- -");
            let bare = format!("{argv0}\0-\0");
            assert_eq!(script_argument(exe, bare.as_bytes()), None, "{argv0} -");
        }
    }

    #[test]
    fn identities_with_control_characters_are_unknown() {
        assert_eq!(kind("/usr/bin/gi\nt"), CallerKind::Unknown, "a newline would plant a second ACL line");
        assert_eq!(kind("/usr/bin/python3//home/u/a\n/usr/bin/git"), CallerKind::Unknown);
        assert_eq!(kind("/usr/bin/git\t"), CallerKind::Unknown);
        assert_eq!(kind("/usr/bin/gït"), CallerKind::App, "non-ASCII is fine");
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
    fn an_unreadable_pidfd_falls_back_to_the_bus_pid_and_never_straight_to_unknown() {
        use FdPid::*;
        use Resolution::*;
        assert_eq!(resolve(Some(Pid(7)), Some(7)), ByPidfd(7));
        assert_eq!(resolve(Some(Pid(7)), None), ByPidfd(7));
        assert_eq!(resolve(Some(Pid(7)), Some(8)), Unknown, "the bus and the pidfd disagree");
        assert_eq!(resolve(Some(Gone), Some(7)), Unknown, "the process exited");
        assert_eq!(resolve(Some(Unreadable), Some(7)), ByPid(7), "EACCES on fdinfo");
        assert_eq!(resolve(Some(Unreadable), None), Unknown);
        assert_eq!(resolve(None, Some(7)), ByPid(7), "a bus without ProcessFD");
        assert_eq!(resolve(None, None), Unknown);
    }

    #[test]
    fn an_unreadable_fdinfo_is_not_a_gone_process() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let fd = std::os::fd::OwnedFd::from(file);
        // /dev/null is no pidfd: readable fdinfo without a Pid line is Gone
        // on Linux, and unreadable (no /proc) elsewhere.
        let got = pidfd_pid(fd.as_fd());
        assert!(matches!(got, FdPid::Gone | FdPid::Unreadable), "{got:?}");
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
