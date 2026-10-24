//! Private file writes: owner-only permissions, atomic replace.

use std::io::Write;
use std::path::Path;

pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
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
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
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
}
