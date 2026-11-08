use dybw_core::crypto::NativeArgon2;
use dybw_core::ports::{Argon2Input, KdfRunner, PortError};
use zeroize::Zeroizing;

/// Argon2id on the blocking pool, so a 64 MiB derivation never stalls the
/// worker thread's other tasks.
pub struct BlockingArgon2;

impl KdfRunner for BlockingArgon2 {
    async fn argon2id(&self, input: Argon2Input) -> Result<Zeroizing<[u8; 32]>, PortError> {
        // block_on is allowed on a blocking-pool thread, and drives the core's future whatever it awaits.
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || handle.block_on(NativeArgon2.argon2id(input)))
            .await
            .map_err(|_| PortError("the key derivation task failed".into()))?
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::time::Duration;

    fn input() -> Argon2Input {
        Argon2Input {
            password: Zeroizing::new(b"pw".to_vec()),
            salt: [7; 32],
            iterations: 3,
            memory_kib: 65536,
            parallelism: 1,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn argon2_runs_off_the_worker_thread() {
        let local = tokio::task::LocalSet::new();
        let ticks = Rc::new(Cell::new(0u32));
        let t = ticks.clone();
        let (key, seen) = local
            .run_until(async move {
                let ping = tokio::task::spawn_local(async move {
                    loop {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                        t.set(t.get() + 1);
                    }
                });
                let key = BlockingArgon2.argon2id(input()).await;
                ping.abort();
                (key, ticks.get())
            })
            .await;
        assert_eq!(key.unwrap().len(), 32);
        // Run on the worker thread this would stall the ping for the whole derivation and see ~0 ticks.
        assert!(seen > 5, "the worker thread was blocked: {seen} ticks");
    }

    #[tokio::test]
    async fn argon2_rejects_bad_parameters() {
        let mut i = input();
        i.parallelism = 0;
        assert!(BlockingArgon2.argon2id(i).await.is_err());
    }
}
