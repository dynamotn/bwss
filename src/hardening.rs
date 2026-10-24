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
        let none = Rlimit { current: Some(0), maximum: Some(0) };
        [
            failure("PR_SET_DUMPABLE", set_dumpable_behavior(DumpableBehavior::NotDumpable)),
            failure("RLIMIT_CORE", setrlimit(Resource::Core, none)),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// What to log when the syscall `what` returned `result`; nothing on success.
    fn failure(what: &str, result: Result<(), rustix::io::Errno>) -> Option<String> {
        result.err().map(|e| format!("{what}: {e}"))
    }

    #[cfg(test)]
    mod tests {
        use rustix::io::Errno;

        use super::*;

        #[test]
        fn a_failed_syscall_is_named_and_a_successful_one_is_silent() {
            assert_eq!(failure("PR_SET_DUMPABLE", Ok(())), None);
            assert_eq!(
                failure("RLIMIT_CORE", Err(Errno::PERM)),
                Some(format!("RLIMIT_CORE: {}", Errno::PERM)),
                "the failure names the syscall and the errno"
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    pub fn harden() -> Vec<String> {
        Vec::new()
    }
}
