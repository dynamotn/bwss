//! Process hardening at daemon start (TM-013): no core dump and no attach.
//!
//! Linux only. `mlock` is deliberately not used (docs/design.md §11).

/// What `harden` could not set; the daemon logs it and keeps running.
pub fn harden() -> Vec<String> {
    imp::harden()
}

#[cfg(target_os = "linux")]
mod imp {
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

    pub fn harden() -> Vec<String> {
        let mut failed = Vec::new();
        if let Err(e) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
            failed.push(format!("PR_SET_DUMPABLE: {e}"));
        }
        let none = Rlimit { current: Some(0), maximum: Some(0) };
        if let Err(e) = setrlimit(Resource::Core, none) {
            failed.push(format!("RLIMIT_CORE: {e}"));
        }
        failed
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    pub fn harden() -> Vec<String> {
        Vec::new()
    }
}
