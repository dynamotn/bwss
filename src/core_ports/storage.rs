use crate::config::Paths;
use crate::fsutil;
use dybw_core::ports::{PortError, Storage};
use std::path::PathBuf;

/// The core's blobs as files. `"device"` is the existing per-profile device
/// id file; every other key lives in `<tool state>/core/<key>`.
pub struct FileStorage {
    device: PathBuf,
    dir: PathBuf,
}

impl FileStorage {
    pub fn new(paths: &Paths, profile: &str) -> Self {
        FileStorage { device: paths.device_id(profile), dir: paths.tool_state.join("core") }
    }

    fn path(&self, key: &str) -> Result<PathBuf, PortError> {
        if key == "device" {
            return Ok(self.device.clone());
        }
        let ok = !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b));
        if ok { Ok(self.dir.join(key)) } else { Err(PortError("invalid storage key".into())) }
    }
}

fn io(e: std::io::Error) -> PortError {
    PortError(format!("storage: {}", e.kind()))
}

impl Storage for FileStorage {
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, PortError> {
        match tokio::fs::read(self.path(key)?).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io(e)),
        }
    }

    async fn save(&self, key: &str, data: &[u8]) -> Result<(), PortError> {
        let (path, data) = (self.path(key)?, data.to_vec());
        tokio::task::spawn_blocking(move || fsutil::write_private(&path, &data))
            .await
            .map_err(|_| PortError("storage task failed".into()))?
            .map_err(io)
    }

    async fn remove(&self, key: &str) -> Result<(), PortError> {
        match tokio::fs::remove_file(self.path(key)?).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io(e)),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn paths(dir: &std::path::Path) -> Paths {
        let home = dir.as_os_str().to_owned();
        Paths::with(|v| (v == "HOME").then(|| OsString::from(&home)))
    }

    #[tokio::test]
    async fn storage_maps_device_to_the_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let s = FileStorage::new(&p, "default");
        assert_eq!(s.load("device").await.unwrap(), None);
        s.save("device", b"id-1").await.unwrap();
        assert_eq!(std::fs::read(p.device_id("default")).unwrap(), b"id-1");
        s.save("marks", b"m").await.unwrap();
        assert_eq!(std::fs::read(p.tool_state.join("core/marks")).unwrap(), b"m");
        assert_eq!(s.load("marks").await.unwrap().unwrap(), b"m");
        s.remove("marks").await.unwrap();
        s.remove("marks").await.unwrap();
        assert_eq!(s.load("marks").await.unwrap(), None);
    }

    #[tokio::test]
    async fn storage_rejects_path_keys() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileStorage::new(&paths(dir.path()), "default");
        for k in ["", "../x", "a/b", ".hidden", "a.b"] {
            assert!(s.save(k, b"x").await.is_err(), "{k}");
        }
    }

    #[tokio::test]
    async fn storage_reports_a_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        std::fs::create_dir_all(p.tool_state.join("core/dir")).unwrap();
        let s = FileStorage::new(&p, "default");
        assert!(s.load("dir").await.is_err());
        assert!(s.remove("dir").await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn storage_writes_private_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let s = FileStorage::new(&p, "default");
        s.save("marks", b"m").await.unwrap();
        s.save("device", b"d").await.unwrap();
        for f in [p.tool_state.join("core/marks"), p.device_id("default")] {
            assert_eq!(std::fs::metadata(f).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
