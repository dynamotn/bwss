//! Private file writes (owner-only permissions, atomic replace), and who
//! may write a file.

use std::io::Write;
use std::path::Path;

pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic(path, data, 0o600)
}

/// Replaces `path` atomically with a file of permission bits `mode`.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        create_private_dir(dir)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        let mut f = opts.open(&tmp)?;
        // The umask may have taken bits away: set exactly `mode`.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Serializes `value` first and writes only a complete document: when it
/// cannot be serialized the file on disk is left as it was.
pub fn write_json_private(path: &Path, value: &impl serde::Serialize) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    write_private(path, &bytes)
}

/// Creates `dir` (and its parents) with mode 0700, and tightens `dir`
/// itself to 0700 when it already exists with more.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    create_private_dir(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir)?.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode & 0o700))?;
        }
    }
    Ok(())
}

/// The user this process runs as, for "could this user write that file?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Effective user id.
    pub uid: u32,
    /// Effective and supplementary group ids; `None` when unknown, in which
    /// case every group counts as the user's.
    pub groups: Option<Vec<u32>>,
}

impl User {
    #[cfg(target_os = "linux")]
    pub fn current() -> std::io::Result<User> {
        let status = std::fs::read_to_string("/proc/self/status")?;
        user_from_status(&status)
    }

    /// Without `/proc`: a new file is owned by the effective user id.
    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn current() -> std::io::Result<User> {
        use std::os::unix::fs::MetadataExt;
        let probe = tempfile_path();
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&probe)?;
        let uid = file.metadata().map(|m| m.uid());
        let _ = std::fs::remove_file(&probe);
        Ok(User { uid: uid?, groups: None })
    }

    /// Whether this user can change a file with these permission bits: as
    /// root, as its owner (who may chmod it), or through a write bit.
    pub fn may_write(&self, mode: u32, owner: u32, group: u32) -> bool {
        if self.uid == 0 || owner == self.uid || mode & 0o002 != 0 {
            return true;
        }
        mode & 0o020 != 0 && self.groups.as_ref().is_none_or(|groups| groups.contains(&group))
    }

    #[cfg(unix)]
    pub fn may_write_file(&self, meta: &std::fs::Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;
        self.may_write(meta.mode(), meta.uid(), meta.gid())
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn tempfile_path() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("bwss-uid-{}-{nanos}", std::process::id()))
}

#[cfg_attr(all(not(target_os = "linux"), not(test)), expect(dead_code, reason = "Linux only; tested everywhere"))]
fn user_from_status(status: &str) -> std::io::Result<User> {
    parse_status(status).ok_or_else(|| std::io::Error::other("cannot read the user from /proc/self/status"))
}

/// The effective uid and the groups from `/proc/<pid>/status`.
#[cfg_attr(all(not(target_os = "linux"), not(test)), expect(dead_code, reason = "Linux only; tested everywhere"))]
fn parse_status(status: &str) -> Option<User> {
    let field = |name: &str| status.lines().find_map(|l| l.strip_prefix(name)).map(str::split_whitespace);
    let effective = |name: &str| field(name)?.nth(1)?.parse::<u32>().ok();
    let uid = effective("Uid:")?;
    let mut groups: Vec<u32> = field("Groups:")?.map(str::parse).collect::<Result<_, _>>().ok()?;
    groups.push(effective("Gid:")?);
    Some(User { uid, groups: Some(groups) })
}

pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    struct Unserializable;

    impl serde::Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("cannot serialize"))
        }
    }

    #[test]
    fn save_failure_never_writes_an_empty_file() {
        let dir = std::env::temp_dir().join(format!("bwss-fsutil-{}", std::process::id()));
        let path = dir.join("state.json");
        write_json_private(&path, &serde_json::json!({ "kept": true })).unwrap();
        let err = write_json_private(&path, &Unserializable).unwrap_err();
        assert!(err.to_string().contains("cannot serialize"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"kept":true}"#);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_in_a_directory_that_cannot_be_created_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("a-file");
        std::fs::write(&blocker, b"x").unwrap();
        assert!(write_private(&blocker.join("child/state.json"), b"{}").is_err());
        assert_eq!(std::fs::read(&blocker).unwrap(), b"x", "the blocking file is untouched");
        assert!(ensure_private_dir(&blocker.join("sub")).is_err());
    }

    #[test]
    fn a_status_without_the_ids_is_an_error_naming_the_file() {
        let e = user_from_status("Name:\tbwss\n").unwrap_err();
        assert!(e.to_string().contains("/proc/self/status"), "{e}");
        let ok = user_from_status("Uid:\t1\t2\t2\t2\nGid:\t3\t4\t4\t4\nGroups:\n").unwrap();
        assert_eq!(ok, User { uid: 2, groups: Some(vec![4]) });
    }

    #[test]
    fn a_path_without_a_parent_cannot_be_written() {
        assert!(write_atomic(Path::new(""), b"x", 0o600).is_err());
        assert!(write_atomic(Path::new("/"), b"x", 0o600).is_err());
    }

    #[test]
    fn the_user_comes_from_the_effective_ids() {
        let status = "Name:\tbwss\nUid:\t1000\t1001\t1001\t1001\nGid:\t100\t101\t101\t101\nGroups:\t10 20 \n";
        assert_eq!(parse_status(status), Some(User { uid: 1001, groups: Some(vec![10, 20, 101]) }));
        assert_eq!(parse_status("Uid:\t1\t2\t2\t2\nGid:\t3\t4\t4\t4\nGroups:\n").unwrap().groups, Some(vec![4]));
        assert_eq!(parse_status("Uid:\t1\n"), None);
        assert_eq!(parse_status("Uid:\t1\t2\nGid:\t3\t4\nGroups:\tx\n"), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_current_user_owns_the_files_it_creates() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let me = User::current().unwrap();
        assert_eq!(std::fs::metadata(dir.path()).unwrap().uid(), me.uid);
        assert!(me.may_write_file(&std::fs::metadata(dir.path()).unwrap()));
    }

    #[test]
    fn who_may_write_a_file() {
        let user = User { uid: 1000, groups: Some(vec![50]) };
        assert!(user.may_write(0o444, 1000, 0), "the owner may chmod");
        assert!(!user.may_write(0o755, 0, 0));
        assert!(user.may_write(0o757, 0, 0));
        assert!(user.may_write(0o775, 0, 50));
        assert!(!user.may_write(0o775, 0, 51));
        assert!(User { uid: 0, groups: Some(vec![]) }.may_write(0o555, 1, 1), "root writes anything");
        assert!(User { uid: 1000, groups: None }.may_write(0o775, 0, 51), "unknown groups count as ours");
    }

    #[cfg(unix)]
    #[test]
    fn private_dirs_are_created_or_tightened_to_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let new = dir.path().join("a/b");
        ensure_private_dir(&new).unwrap();
        assert_eq!(std::fs::metadata(&new).unwrap().permissions().mode() & 0o777, 0o700);
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&new).unwrap();
        assert_eq!(std::fs::metadata(&new).unwrap().permissions().mode() & 0o777, 0o700);
    }
}
