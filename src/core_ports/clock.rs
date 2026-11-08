use dybw_core::ports::Clock;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }

    async fn sleep_ms(&self, ms: u64) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn clock_reads_the_epoch_and_sleeps() {
        assert!(SystemClock.now_ms() > 1_700_000_000_000);
        let start = tokio::time::Instant::now();
        SystemClock.sleep_ms(250).await;
        assert!(start.elapsed() >= std::time::Duration::from_millis(250));
    }
}
